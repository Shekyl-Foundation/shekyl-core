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
check clears `SimpleRequestRpc`.) The check has **two axes, not one**: (a) the connection pool
(above), and (b) **the resolver** — some HTTP stacks share a process-wide DNS resolver /
happy-eyeballs cache across clients, which is a cross-persona correlation point *above* the SOCKS
proxy, the same class of leak as a shared pool. Almost certainly moot for `.onion`-over-SOCKS
(Tor resolves, not the client), but the source-check must **confirm** the hostname never reaches a
client-side resolver, not assume the proxy binding is the only shared-state axis.

**Verdict (source-checked 2026-07-02 — `PRpc`, and the check found a live leak).** The four-axis
check — pool / resolver / reconnect-auth, each graded *structural* (cannot regress without a
signature change) vs *configured* (holds by setup, can regress silently under a dep bump):

| candidate | A pool | B resolver | C reconnect-auth |
| --- | --- | --- | --- |
| `SimpleRequestRpc` (`simple-request`/hyper) | isolated-structural (fresh client/call) | **unsupported** — *no SOCKS code at all*, always client-side `getaddrinfo` | **unsupported** — no SOCKS auth to re-present |
| `PRpc` over `PTorClient`/`ureq::Agent` | isolated-structural (per-`Agent` owned pool) | isolated-**configured** (needs `socks5h`+`resolve_target(false)`) | isolated-structural (immutable `Arc<Config>` re-presented verbatim on every re-dial) |

- **`SimpleRequestRpc` collapses at Axis B:** `simple-request 0.2.0` has *no proxy/SOCKS code*
  (zero grep hits) and always resolves targets via hyper's `GaiResolver` — making it Tor-capable
  means writing a new connector stack, i.e. *more* work than `PRpc` and with no structural floor.
  **Decision: `PRpc` over the SP-T1 `ureq::Agent`.** The async/sync seam is `spawn_blocking` (the
  established workspace idiom); the `Agent` is cheap-`Clone` (Arc), so `post` clones it into the
  closure with no shared state.
- **Axis B is graded *configured* honestly — because the dependency offers no structural option** —
  and it was found **configured *wrong* in landed SP-T1 code**: the proxy was built as `socks5://`,
  which ureq defaults to *resolve-locally*, so every persona's target hostname was leaking to the OS
  resolver (a cross-persona correlation point) and `.onion` was broken outright. SP-T1's measured
  test proved *circuit* isolation while dialing IPs — it never proved the *target* rode the circuit.
  **Fixed as a landed-behavior bug** (commit — `fix(p-transport)!: close the per-P DNS leak`),
  hardened to the maximum structure the dep allows: the **typed** `ProxyProtocol::Socks5h` enum (a
  wrong enum is a compile error; the wrong *scheme string* was the silent one-char bug) + an
  **explicit `resolve_target(false)`** (pins it independent of ureq's drifting scheme default) +
  **verified at source** that nothing resolves the target upstream of Tor (`resolver.empty()` branch;
  `uri.host_port()` handed to the proxy by name). And the fail-open hazard — absent ureq's
  `socks-proxy` feature, ureq dials **direct**, deanonymizing silently — is closed at **compile
  time**: a required `tor-socks` feature forwards it with a `compile_error!` on absence, because
  feature unification means a runtime test cannot prove production has the feature.
- **The durable lesson (record it — the next transport surface will need it).** The leak existed
  because per-`P` isolation was *tested at the circuit layer and assumed at the target layer*.
  **"Isolation" is not one property — it is a stack of separable ones: circuit, target-resolution,
  connection-reuse, reconnect-identity — each independently correct or broken.** The four-axis
  decomposition is the **standing model** for any future isolation claim: whenever code claims
  "per-`P` isolation," the question is *on which axes, proven how (structural vs configured)*. SP-T3's
  onion-serving side (`ADD_ONION`) will have its own version of these axes; **"SP-T2 proved
  isolation" is exactly the over-broad claim that would hide the next target-layer leak** — so an
  isolation claim is only ever *"axis X, proven structural/configured by Y,"* never unqualified.
  **The four axes above are the *client* half (circuit / target-resolution / connection-reuse /
  reconnect-identity).** The onion-*serving* side has a symmetric, not-yet-enumerated set:
  descriptor-publication timing (do N personas publish in a correlated burst?), the shared HSDir set
  (do their descriptors land on overlapping directories, correlatable by the HSDir?), and
  introduction-point reuse. **SP-T3 must open by enumerating its serving axes** — "SP-T2 proved the
  client axes" must not become the over-broad claim that hides a serving-side correlation (the same
  trap, other direction). This is a flag for SP-T3, not SP-T2 work.

### DQ-T2.3 — posture→impl selector (no conflation)

`local` ⇒ direct-localhost `BlockSource`; `remote` (own-remote ② / untrusted ③) ⇒
`PBlockSource(PTorClient)`. Enforced structurally: `PBlockSource::new(client: PTorClient)` is the
**only** constructor — no principal `DaemonClient` path, no `Default` (§416). The selector lives at
the SP-5 scan-loop wiring, and must make "a local posture routes its fetch over a shared network
circuit" **unrepresentable**, not merely discouraged.

**The no-silent-③ property (the enforcement that makes "discouraged" real).** "Third-party daemons
are discouraged" (§5) is a documentation state; the selector is where the code either enforces it or
doesn't. The wargame: can a user land in posture ③ *without an explicit, informed choice* — a config
default that points at a public node, an auto-discovery, a "local node unreachable, falling back to
X" convenience path? If yes, "discouraged" is aspirational and a silent user inherits every §5
residual without having chosen the posture that carries them. So the selector carries a build-time
property: **③ is reachable only by explicit selection** — never a default, never a fallback, with
the §5 residuals surfaced at the point of choice (a friction-carrying opt-in). No posture enum
exists in code yet, so this is cheap to get right at birth: the posture type has no `Default` impl,
and no code path constructs ③ from a failure of ①/② (a dead local node is an *error the user sees*,
not a silent re-posture).

*Audited at source (2026-07-02): the property holds today by absence* — every production default is
loopback (CLI `--daemon-address` → `localhost:11028`, `main.rs:43`; GUI → `127.0.0.1:{port}` +
detect-local-else-spawn-local sidecar, `daemon_manager.rs:92-160`; the engine library never picks a
URL — `DaemonClient::new` wraps what the embedder passes); no public-node default, no
auto-discovery, no localhost-else-remote fallback anywhere; `WalletPrefs` deliberately carries no
daemon-address field. Two watch-items the build encodes: (a) the GUI's `DaemonMode
{Managed, External, Unavailable}` classifies process *ownership*, not remoteness — it is not a
posture enum and must not be mistaken for one; (b) the inherited C++ carries `get_public_nodes()`
remote-node-discovery machinery (`wallet2.cpp:13374`) — a **pattern the Rust stack consciously does
not inherit**; the no-silent-③ property is the standing refusal.

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
   for `local`** — loopback enumeration is an operating-system fact, not an RPC one. **But the
   residual is observable only from the box itself**, and that bounds it operationally: an adversary
   positioned to read your loopback TCP table already has local presence, and local presence carries
   strictly stronger tools (`/proc`, wallet memory, ptrace) — the connection count is the *least* of
   that adversary's capabilities. So this residual does **not** argue for handing the scan to a
   stranger's daemon. Re-derived on both privacy axes (§5), **`local` — run your own node — is the
   privacy default**, and this residual is its honestly-stated floor: *off-box, `local` leaks
   nothing; on a compromised box, the persona count is visible and is the least of your problems.*
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
   activity, in absolute time — not a signal/no-signal boolean. *(The fork below is the
   pre-measurement decision procedure, kept as the decision record; the **settled disposition**
   follows the ladder.)* The fork:
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

     **Settled (Round-0 measured 2026-07-02 + the §5 posture re-derivation) — engineering reasons
     first, threat math demoted:**
     - **Rung 1 adopted — as correct architecture, not as closing a live channel.** The per-`P`
       block read is served by the **single-height lock-free read**: simpler (no shared lock on a
       read that never needed one), measurably better under load (the lock amplifies contention ~4×
       at CPU saturation — §3 results), and consistency-confirmed under a forced writer window. The
       timing channel it removes is load-bearing in **neither** posture: in `local` it is **subsumed
       by enumeration** — any adversary able to measure sub-ms cross-persona timing on your box can
       read `/proc/net/tcp` directly (strictly more capability for strictly less information); in
       `remote` it is a residual of a posture we **actively discourage** (§5). Rung 1 exists
       *because the RPC server is ours.*
     - **Rung 2 not adopted, with the reason recorded:** the attack it would defend against (patient
       statistical averaging of the residual coupling by a shared-daemon operator) is an attack on
       the discouraged posture — we state it as a reason remote is discouraged (§5) rather than
       harden a path we tell people not to use. **Reopen:** if `remote` is ever promoted to a
       supported posture, rung 2 reopens as *coherence-destruction* (per-persona fetch-time jitter),
       not magnitude reduction.
     - **Rung 3 moot** — rung 1 side-steps the lock; the residual left is scheduler-level, not lock.
     - **The timing reopens (R-T1/R-T2) close with rationale, not stay open:** the coupling numbers
       are **architectural characterization, not a live-channel measurement** — the local timing
       channel is dominated by the documented enumeration residual. The one reopen is a **posture
       change** (remote promoted to supported), which reopens timing, arrival-sync, and scan-pattern
       together as first-class.
     - **P-SH — the lone load-bearing precondition, and it is *correctness*, not privacy.** The
       per-`P` lock-free read is **single-height-per-snapshot**. A straddled multi-height read is a
       wrong scan result with **no adversary at all**, so no threat-model concession touches it —
       dominance arguments retire threat channels; they never touch correctness invariants.
       Enforcement is the **type, not a comment**: `BlockSource::block_at(height)` takes one height,
       so batching heights into one response is unrepresentable without changing the one signature
       whose doc carries the reopen (*batching reopens finding-b; it requires a single-txn batch
       read, or the scanner's cross-height coherence requirement established first*). The comment
       explains; the type enforces.

   **The sequence-coherence keystone (verified at source 2026-07-02 — one bug found).** P-SH alone
   is *not* the whole correctness story: it makes each **read** atomic, but the scanner processes a
   *sequence* of single-height reads, and a reorg landing between `fetch(H)` and `fetch(H+1)` hands
   the sequence H from the old chain and H+1 from the new one. P-SH prevents torn reads; only the
   consumer's **prev-hash linkage check on append** prevents torn *sequences* — rung 1's correctness
   rests on the **pair**. "The scanner is straddle-indifferent" was the round's one load-bearing
   claim established by trace rather than exercised, so it was verified per consumer path:
   - **P-scan (the path SP-T2 feeds): verified.** `verify_exhaustive`
     (`pscan/exhaustiveness.rs:276-313`) checks `previous == recomputed-hash` on **every consecutive
     pair**, anchored at the sealed `frontier_hash` (persisted in the `PScanState` cursor); mismatch
     = `ContinuityBreak` → **loud task halt, deliberately no rewind** (the verified `(height, hash)`
     frontier exists to forbid a resume-splice) — never silently wrong. Exposure is additionally
     structural: the P-scan reads only below the finality horizon (`tip − ARCHIVAL_REORG_DEPTH_BLOCKS
     = 720`), so a straddle in its range requires a 720-deep reorg.
   - **`shekyl-scanner`: strictly per-block by design** — it never reads `header.previous`; linkage
     responsibility lives entirely in the calling loops. Correct placement; no change.
   - **The principal refresh loop: bug found (fixed as build slice 0).** The reorg check
     (`local_refresh.rs:640-646`) compares `header.previous` against `snapshot.block_hash_at(h−1)` —
     but the snapshot is the **pre-attempt persisted window** (≤ `synced_height`), so for every
     consecutive pair fetched *within* one attempt the lookup returns `None` and the check is
     **skipped**; the hashes fetched this attempt are accumulated but never consulted. A mid-attempt
     reorg therefore splices a torn sequence silently (sole backstop: the merge-side curve-tree root
     verify, which catches the splice *iff* the branches' leaf sets differ). **Path-independent:**
     the locked `get_block` has the identical exposure — the lock never spanned separate RPC calls —
     so this is a pre-existing bug the keystone check surfaced, not a rung-1 regression. *Fix:*
     extend the check to track the running last-fetched hash (covering intra-attempt pairs), reusing
     the existing `find_fork_point` → `ReorgRewind` rewind arm; prove it with a mid-attempt
     `replace_chain_from` test (the `TestDaemon` helper exists and is currently only self-tested).

**Why measure *now*, not when the fetch path exists (the sharp reason):** the measurement's *result
changes the wallet-side design*. If #2's coupling magnitude survives the remote-threat evaluation
(§3b), the **remote** `PBlockSource` acquires a timing-decorrelation responsibility (a design
decision in DQ-T2.2/T2.3); if it does not, `PBlockSource` is a plain fetch shim. Freezing the
`PBlockSource` design *before* the measurement means either over-building a decorrelation shim
speculatively (violating get-it-right-not-speculatively) or under-building and retrofitting. Measure
first, and `PBlockSource` knows what it is responsible for. **Measured: it is responsible for
fetching.** The decorrelation duty did not attach (rung 2 not adopted) — `PBlockSource` is a plain
fetch shim.

---

## 2b. Build invariants (slices 1–6) — where a new path could reopen a closed hole

The pre-build round found two `!`-fixes (the intra-attempt reorg splice, the per-`P` DNS leak) in
code whose *shape* was reviewed and right — a property underneath was silently broken. The lesson:
**"proven" means "proven on the path checked," and the build adds paths.** Each invariant below is a
place a slice could reintroduce what the round just closed; they are build-binding, not advisory.

1. **One agent construction site, and it is the hardened one (Axis B can't regress by a second
   path).** The DNS-leak fix + the `socks5h`/`resolve_target(false)` + the `tor-socks` compile-guard
   all live in `PTorClient::for_persona` (`shekyl-p-transport`), and the DNS regression test covers
   *that* constructor. So `PRpc`/`PBlockSource` **must not** build a `ureq::Agent` (or any HTTP
   client) themselves — they take a `PTorClient` and use `PTorClient::agent()`. No
   `Agent::config_builder()` anywhere but `for_persona`; the safe construction is the *only*
   construction (the `VerifiedTorBinary` shape). A second inline agent build is a new, uncovered
   Axis-B surface — treat it as the same class of defect as the leak it would recreate.
2. **The blocking pool is a *fifth axis* — a shared runtime resource the per-circuit isolation does
   not cover.** `PRpc::post` bridges sync `ureq` into async via `spawn_blocking` (the workspace
   idiom), which has two edges the idiom does not handle for free:
   - **Cancellation drains, it does not cancel.** A `spawn_blocking` task in a synchronous `ureq`
     call is not a cancellation point — on scan cancel / wallet close / `ctx.stop()` it runs to
     completion or its own timeout. So `PRpc` **must** set explicit, short-ish `ureq` connect+read
     timeouts (a stalled/building Tor circuit can hang a read far longer than a direct dial), and the
     design accepts that in-flight fetches *drain* on shutdown. This couples to `TorService` teardown
     ordering: the blocking fetches must drain **before or independently of** the control-connection
     teardown, or a fetch outlives the Tor it is fetching through — a shutdown-ordering constraint the
     selector/lifecycle slice owns.
   - **Bounded per-`P` fetch concurrency.** tokio's blocking pool is bounded (512 default) and
     **shared** with the scan offload (`pscan/scan_step.rs`) and the daemon-rpc handlers. N personas
     each holding a blocking thread on a slow Tor fetch must stay well below the pool, or a
     many-persona wallet starves *unrelated* `spawn_blocking` work. The per-`P` fetch concurrency is
     bounded (a semaphore at the scan-loop wiring), and the bound is stated where it lands.
3. **The posture selector *refuses on absence*, it does not degrade (no-silent-③, adversarially
   tested).** The enforcement is not "explicit ③ works" but an adversarial test: construct the
   selector with **no posture chosen** and the **local node unreachable**, and assert it **errors** —
   never falls through to a remote/public default. The failure mode to forbid is the convenience
   reflex "local node down → fall back to a public node so the wallet still works," which silently
   lands a user in the discouraged posture with every §5 residual. The test codifies *breaking is
   correct here* so a later "the wallet shouldn't just break" optimization trips a red test, not a
   silent re-posture. (DQ-T2.3.)

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

### Round-0 results (measured 2026-07-02)

**Envelope** (a disposition is "safe *under these conditions*"): regtest/FAKECHAIN `shekyld`,
~2 s/block coinbase-only chain, tip 41, probe + up to 16 contending personas on an 8c/16t i9-11950H;
harness `engine::daemon_observability` (`#[ignore]`d, `SHEKYLD_BIN`), one consolidated run (~170 s).
A larger-block / higher-write mainnet is outside this envelope; so is N ≫ 16.

- **M-enum — confirmed as specified.** 30/30 clients connected (the dead epee cap gates nothing);
  the count was visible only in the host TCP table (31 ESTABLISHED); `get_info.rpc_connections_count
  = 0`. The leak is OS-level, below the RPC surface.
- **M-timing — a saturation *cliff*, not a slope.** Both paths are ~flat to 8 contenders; the entire
  signal is the N=16 cliff (= the box's thread count): locked `get_block` p90 2314→4244 µs vs
  lock-free `.bin` 937→1241 µs — under CPU saturation the lock amplifies contention **~4×**
  (lock-isolated coupling ≈ 1.6 ms at the cliff). At N = threads the measurement cannot cleanly
  separate lock-contention from CPU-saturation; given the settled disposition, it does not need to.
- **M-substitute — named and sourced.** The lock-free path keeps ~304 µs of coupling, also only at
  the N≈cores cliff → scheduler/worker-pool saturation, **not** LMDB (the read txn is
  per-call-fresh). A smaller instance of the same channel; recorded, not adjectived away.
- **M-consistency — conclusive under a *forced* window.** The harness brackets every read with a
  writer-commit counter and **fails as inconclusive if no read provably raced a commit** (a
  quiet-run green cannot pass). Measured: 19 reads raced a commit (14 single-height + 5 batch);
  4 725 stable-height cross-path pairs byte-identical; 2 416 present tip reads, 0 torn/mis-height;
  0 straddles. **Finding-b was *not* empirically exercised and cannot be forced by
  `pop+regenerate`** — top-down pop + bottom-up regen never presents an inconsistent adjacent-height
  pair, so only a genuine competing-chain reorg stages the straddle. It therefore stays
  **source-established + structurally excluded by P-SH** (single-height reads), not "empirically
  passed" — the denominator is recorded so a green result cannot mean "the race never fired."
- *(Noted for the build, not measured: the scanner's tx fetch (`get_transactions`, by-hash) cannot
  straddle heights; and the `.bin` route incidentally returns block+txs in one response — whether
  the build collapses the fetch triple is a build-slice question.)*

---

## 4. Decomposition (commit-slices — one PR unless it grows exceptionally large)

Per the ~10-commit-as-CI-cost-guideline, one reviewable PR, sliced by commit:

0. **The sequence-coherence fix (the keystone bug, first — nothing builds on an unverified
   keystone):** extend the principal refresh loop's reorg check to cover **intra-attempt**
   consecutive pairs via the running last-fetched hash (`local_refresh.rs:640` today skips them),
   reusing the existing `find_fork_point`/`ReorgRewind` arm; proven by a mid-attempt
   `replace_chain_from` straddle test. Pre-existing, path-independent (the locked read has the same
   exposure), so it lands regardless of the rest of the PR.
1. **Framing + docs** — correct §367 (add-not-replace), the §4 posture enumeration read-model,
   this Round-0 doc's decisions.
2. **`DaemonBlockSource` per-`P` direct connection** (DQ-T2.4) — with the enumeration tension stated.
3. **The RPC-over-Tor transport** (DQ-T2.2) — the source-verified per-`P`-isolated `Rpc`
   (`SimpleRequestRpc`-per-instance or `PRpc`), with an isolation KAT.
4. **`PBlockSource`** (DQ-T2.1/.3) — `new(client)` only, `tip_height`/`block_at` over #3 reusing
   `default_fetch_scannable_block`; a **plain fetch shim** — the Round-0 disposition attached **no**
   decorrelation duty (rung 2 not adopted; reopens only on posture promotion).
5. **Posture→impl selector** at the scan-loop wiring (DQ-T2.3) — local→direct, remote→`PBlockSource`,
   conflation unrepresentable.
6. **Rung-1 fetch routing** — serve the per-`P` block read via the **single-height lock-free read**
   (an in-scope Rust RPC-layer change, gated green by the Round-0 M-consistency diff), with the
   **P-SH note on the `block_at(height)` signature** — the type is the enforcement, the comment
   carries the finding-b reopen. The Round-0 results + settled disposition are recorded in this doc
   (§3 results, DQ-T2.5 settled block); no open daemon reopens remain except the posture-change one.

The `Ok(None)` provable-absence property (withheld-body robustness) is **out of scope for SP-T2** —
it is header-chain-anchoring work (a later 2d-2 robustness slice); `PBlockSource` inherits
`DaemonBlockSource`'s "missing ⇒ `Err`" until then. (Rule-21 reopen: the withheld-body robustness
slice.)

---

## 5. The §4 posture read-model (re-derived on both axes — lands in the transport plan)

The round initially weighed one axis — persona unlinkability — and drifted toward remote-over-Tor
as the privacy default. Weighing **both** axes inverts the recommendation, and the operational
reality settles it:

- **Scan-pattern confidentiality:** `local` leaks *nothing off-box* — no scan heights, no persona
  count, no timing; the scan never leaves the machine. `remote` shows a stranger's daemon the scan
  itself: Tor anonymizes *who* is scanning, not *what* is scanned.
- **Persona unlinkability:** `local`'s enumeration residual is observable only under local
  compromise, where the adversary already has strictly stronger tools (`/proc`, wallet memory,
  ptrace). `remote` unlinks personas on the network path but re-exposes them to the terminating
  daemon.

**Recommendation: run your own node** (transport plan ① local, or ② your own remote node — both
terminate the scan at *your* daemon). `local` is the privacy-maximizing default — nothing leaves
the box, and the one residual bites only an already-compromised host. **Third-party daemons (③) are
actively discouraged** — for staking or anything else — and the per-`P` Tor path (SP-T1/SP-T2's
`PBlockSource`, which serves ② and ③ alike) exists as the *fallback for users who genuinely cannot
run a node*, with ③'s costs disclosed rather than silently hardened (the silent-compliance lens:
disclosed-cost). The residual list — the *reasons* ③ is discouraged:

1. **Scan-pattern exposure:** the terminating daemon sees N per-circuit connections and every
   height each one requests; per-connection height trajectories are also **cross-session
   fingerprints** — a persona resuming its monotonic scan is linkable across fresh circuits.
2. **Arrival-synchronized fetching:** in steady state every new block triggers all N personas to
   fetch the same tip within a small window over their own circuits — a deterministic, always-on
   correlation at the terminating daemon that no lock work touches.
3. **Residual timing coupling** (§3 results: ~0.3 ms scheduler-level post-rung-1; ~4× lock
   amplification pre-rung-1), which a daemon operator who controls their own load could in
   principle average up over a long scan.

These are recorded as **why-remote-is-discouraged residuals, not `PBlockSource` mitigation
duties**. Hardening any of them (fetch-time jitter, decoy fetches, …) reopens only on a posture
promotion (remote → supported), per the DQ-T2.5 settled disposition. The same two-axis statement
lands in `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §4.
