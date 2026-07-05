# 2d-2 SP-T4a — the per-`P` broadcast seam (Round 0)

**Status:** Round-0 design. Settles the broadcast-③ posture question (forbid, by
type) and freezes SP-T4a's threat model. Consumer: the discretionary
entry/bond-post broadcast (`stake_engine.rs` `JoinMarketVin` — built + signed,
timing draw present, submission deferred behind `TODO(2d)`). Sibling of
[`ARCHIVAL_BOND_2D2_SP_T2_FETCH.md`](ARCHIVAL_BOND_2D2_SP_T2_FETCH.md) (the read
side); refines [`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md)
§12/§15 SP-T4.

---

## 0. What SP-T4a is — the write-side firewall, split from its gated half

SP-T4 (transport plan §12) is "**all `P` broadcasts** — origin-in-`P`-space
always (CX-2), the write-side mirror of SP-T2." It has two consumers with very
different readiness, so it splits:

- **SP-T4a (this doc — buildable now):** the CX-2 write-side seam (a
  `P`-scoped `TransactionSubmitter`, no principal path) + the broadcast
  posture-selector, **proven by its own dead-proxy test (slice 2)** — the
  submitter accepts real wire bytes, maps a transport failure to
  `DaemonAmbiguous`, and never leaks the SOCKS username. Its *real* consumer —
  the discretionary `_spread`/`_bond_first` entry/bond-post broadcast — is
  **not wired here** and cannot be: the bond vin is built + signed today
  (`build_join_market_vin`) and the anchor-free draw exists
  (`draw_entry_gap_guarded`), but the submission needs tx-assembly + a
  submitter/posture/scheduler in `StakeEngine`, all gated on **2c-2a/2c-2b**
  (`TODO(2d)`, `stake_engine.rs`). So the seam ships as the **prerequisite** that
  wiring consumes — a byte-defined-consumer building block, fully tested — not
  consumer-less infrastructure (the SP-0 / SP-T2 bar; contrast SP-T3, whose onion
  had no byte-defined payload at all).
- **SP-T4b (gated — separate slice):** the deadline-critical serve-credit
  challenge-response broadcast. Its tx has a byte-exact wire + on-chain verifier
  (`shekyl-archival-retention`), but **no wallet-side build/sign/submit
  producer** exists yet — that producer is upstream GATE2 wallet work, not
  transport. SP-T4b lands when that producer does; it reuses SP-T4a's seam.

This is **add, not replace** (SP-T2 §0): the principal's broadcast path
(`DaemonTransactionSubmitter<DaemonClient>`) is untouched; SP-T4a adds a
`P`-scoped submitter *beside* it, selected by posture.

---

## 1. The substrate (grounded)

Everything SP-T4a builds on is landed on `dev`:

- **`P`-space transport (already works).** `PTorClient::blocking_post` is a
  general POST (`shekyl-p-transport/src/lib.rs:339`); `PRpc` (`prpc.rs:67`)
  implements `Rpc`, so it **inherits `Rpc::publish_transaction`** (the default
  method over `post` — since the submit-verdict series, posting the typed
  `submit_transaction` route and returning `SubmitVerdict`; at this doc's
  writing it was `send_raw_transaction` → the since-deleted
  `TxRelayResponse`). A tx broadcast over `P`'s own circuit is callable today
  with **zero new transport code**.
- **The submit seam to mirror.** `TransactionSubmitter::submit(tx_bytes) ->
  Result<TxHash, SubmitError>` (`transaction_submitter.rs:34`), impl
  `DaemonTransactionSubmitter<D: DaemonEngine>` (`:52`) — the write-side analogue
  of SP-T2's `BlockSource`/`DaemonBlockSource`. Its live wiring is
  `DaemonTransactionSubmitter<DaemonClient>` (`mod.rs:426`).
- **The idempotent-broadcast contract (already correct).** `TxSubmitOutcome`
  (`traits/daemon.rs:181`) + the §5.2 retry contract: a transport failure is
  **not** an outcome — it is `SubmitError::DaemonAmbiguous` ("ambiguity is the
  absence of a daemon verdict", `:157-165`). Retry is safe **only** because same
  bytes → same txid (hash computed locally, `transaction_submitter.rs:20`) →
  daemon dedupes by hash → `TxSubmitOutcome::AlreadyInPool` /
  `AlreadyInChain` (daemon-attested identity facts under the typed verdict;
  the wallet-side `AlreadyKnown` heuristic this doc originally named was
  retired with the cutover); the path **never rebuilds on retry**.
- **The real consumer.** `build_join_market_vin` (in `shekyl-archival-bond-builder`)
  returns a signed `JoinMarketVin`; `draw_entry_gap_guarded` returns `(_spread,
  _bond_first)`; the submission is the open `TODO(2d)` — all at the bond-post
  handler in `stake_engine.rs` (line numbers omitted; they drift).
- **The read-side enforcement template.** `PBlockSource`
  (`pscan/block_source.rs:196`) — constructible **only** from `PTorClient`, no
  principal path, no `Default`; `Posture`/`select` no-silent-③ selector
  (`posture.rs`). SP-T4a mirrors the *pattern*, not the *type* (see §3).

---

## 2. The threat model — reuse the enforcement pattern, **rebuild** the model

Broadcast is **not symmetric** to fetch on the axis that matters. Fetch is an
idempotent, trace-free **read**: per-`P` isolation on the network path is the
whole job, and the `PBlockSource` mirror covers it. Broadcast is a **write** that
publishes a permanent, globally-visible on-chain artifact and **can fail
ambiguously**. So the `PBlockSource` mirror is correct for the *enforcement
pattern* (no-principal-path-by-type, constructible-only-from-`PTorClient`,
posture-selector shape) and **wrong as a threat model** — it gives zero coverage
on the axes broadcast adds. SP-T4a therefore opens by enumerating the
**broadcast** axes, the same discipline SP-T2 applied to its four client axes
(SP-T2 §DQ-T2.2), but the axes are different:

### Axis 1 — submission-path isolation (the mirror — **covered**)

`P` broadcasts over `P`'s own circuit, never the principal's. This is the direct
write-side mirror of SP-T2, enforced structurally (§3 invariant A). Real, and
the pattern handles it — but it is **one** axis, not the whole job.

### Axis 2 — mempool-arrival timing (**partial — wire the primitive, disclose the residual, do not claim closed**)

*When* `P`'s tx hits the mempool, relative to observable events, is a
correlation no circuit isolation touches. The mitigation primitive exists but is
**narrower than this axis**, and honesty about the gap is load-bearing:

- **What we have.** `shekyl_standoff::draw_entry_gap` (`draw.rs:74`) draws
  `spread ~ U[0, 600 blocks]` + a fair order-inversion coin, per-`P`-independent
  RNG. It decorrelates `P`'s **bond-post from `P`'s own observable funding/entry
  event** — the "bond-post follows a recent spend" ordering prior
  (`shekyl-standoff/src/lib.rs:9-18`; GATE6 §10.12 / GF-7). It is scoped to the
  **entry/bond-post funding seam** — *not* a general "any `P` broadcast" timing
  primitive, *not* a block-anchor decorrelator, *not* a principal-timeline
  decorrelator, *not* a cross-broadcast decorrelator.
- **What SP-T4a does.** *Draws* `draw_entry_gap`'s `(_spread, _bond_first)` at the
  bond-post handler (`stake_engine.rs`), but does **not** wire it into any
  submission — the draw stays on `_`-prefixed locals; wiring it into the broadcast
  (including the `_bond_first` order-coin, not just the `_spread` delay) is the
  **2c-2a/2c-2b** scheduler's job. Applying the built primitive to the one
  broadcast it was designed for is therefore pending, not done (§5 slice 4).
- **What SP-T4a explicitly does NOT close (the GF-7 residual — §4).** The
  broader **principal-timeline** correlation (does `P`'s broadcast timing track
  the principal's lifecycle activity?) is **GF-7**, which GATE6 §10.12 flags
  (S-1) as *the* load-bearing principal↔`P` unlinkability seam **and** the
  least-developed, still **deferred (R3/R4)**, and (S-3) **unmeasured** — no
  `P(link | T_obs)` simulation exists. SP-T4a **must not claim the timing axis
  closed.** It *draws* the narrow funding-seam primitive (wiring it in is 2c's) and
  hands GF-7 forward as a named, deferred residual **and a genesis gate** (§4) —
  not a measured-someday aspiration.

### Axis 3 — first-seen-origin (**new — forbid broadcast-③ by type**)

A broadcast goes to one daemon first, before it propagates: the first-receiving
node learns *"this specific transaction, now permanently on-chain, originated
from the entity on this circuit."* Fetch has no analogue (reads originate
nothing). This decides the broadcast posture model, and it decides it
**differently** from the fetch selector — not as a heavier residual on the same
axis, but as a categorically different leak:

- **Fetch-③** is a **continuous, statistical, unavoidable** leak: a third-party
  daemon learns the *shape* of what you scan; it accumulates over time and
  requires the observer to do inferential work. Fetch is continuous (you cannot
  not-scan). → the fetch selector **allows ③ with disclosure** (SP-T2 §5): an
  informed user accepts a graduated risk.
- **Broadcast-③** is a **discrete, categorical, avoidable** leak: **one**
  broadcast → **one** durable, high-confidence origin fact (the daemon knows it
  saw this txid first, on this circuit), and via GF-7 the tx *content* is a bond
  vin bound to `P` — so first-seen-origin binds the circuit to `P`-bound content
  at the moment of origination. No accumulation, no inference. It **defeats the
  unlinkability property directly** rather than eroding it statistically. And
  broadcast is **rare and discrete** — the "convenience" of broadcasting through
  a stranger is worth almost nothing (you can queue, wait, or use your own node
  for the rare write).
- **The rule that settles it — security-over-features (`00-mission` #1).** The
  feature broadcast-③ enables is negligible; the cost is a permanent, specific,
  on-chain-anchored origin leak on a privacy-critical artifact. Feature worth
  little + cost categorical and irreversible-once-broadcast ⇒ security-over-
  features is not a close call. **Forbid broadcast-③.**
- **The allow/forbid line, stated as a principle (not ad hoc).** Allow-with-
  disclosure tracks **continuous · statistical · unavoidable**; forbid tracks
  **discrete · categorical · avoidable**. Fetch is the former, broadcast the
  latter. The read and write selectors are *deliberately* different types
  because the two operations have different threat models.
- **Wargamed against the forbid** (so it is a decision, not a reflex): is there a
  legitimate user who cannot run their own node and for whom forbidding
  broadcast-③ means they cannot transact at all? Trace it: to **stake** (what
  bond vins are for) you are already running infrastructure; a staker with no
  node of their own is an odd profile, and even a light user who *scans* via ③
  can broadcast via a one-off connection to their own or own-remote node (②) for
  the rare write. The failure mode of forbid is "broadcast through your own
  (①) or own-remote (②) node" — for a privacy coin's staking path, the expected
  posture, not a hardship. Forbid bricks no one who should be broadcasting bond
  vins; it enforces the posture they should already be in. **The forbid holds.**

### Axis 4 — ambiguous partial-failure (**new — the submitter maps honestly; the real recovery contract is 2c's to write**)

A `ConnectionError` on submit does **not** tell you whether the tx propagated —
the daemon may have accepted and relayed it before the response failed. So
"retry on `ConnectionError`" — correct for fetch, and what `PRpc`'s fetch-style
`classify` would hand you — is **wrong** for broadcast if it means "re-derive and
re-submit." The submitter therefore maps **any** transport error to
`SubmitError::DaemonAmbiguous` and stops — disambiguation is not its job:

- `PTransactionSubmitter::submit` maps **any** `Err` from `publish_transaction`
  to `SubmitError::DaemonAmbiguous` — exactly as `DaemonTransactionSubmitter`
  does (`transaction_submitter.rs`). It **does not consult `classify`'s
  transient/permanent verdict** to decide a local retry: absence-of-verdict is
  ambiguous, full stop.
- **The recovery contract is 2c's §5.2 orchestrator to write — from the daemon's
  *real* reply surface, not the `AlreadyKnown` abstraction, which no production
  code derives (only the test double constructs it).** *(Resolved by the
  submit-verdict series, [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md):
  the "real reply surface" is now the typed `SubmitVerdict` — a same-bytes
  retry of a pool-resident tx returns the daemon-attested `AlreadyInPool`, a
  mined one `AlreadyInChain`, and each dangerous window below is a named
  cause with a specified disposition rather than a flag-triage guess.)* The
  dangerous windows as analyzed pre-verdict: a tx *timed out of the pool*
  (→ was `Malformed`; now re-enters full admission — the D3 eviction memory
  is deleted), a *fee floor risen since send* (→ `FeeTooLow` **while the
  original is still mineable** — a false-terminal that must **not** release
  the reservation's output locks; now bounded by the F37 loop-breaker), and
  a *stale FCMP++ root* (now the retryable `StaleRoot`). §5.2's assignment
  of every reply/failure to exactly one of {definitely-relayed,
  definitely-not-relayed, genuinely-ambiguous} is the verdict contract; the
  ambiguous bucket's **TTL exit** is the submit watchdog. Retry =
  re-send the same bytes; **rebuild-on-retry is unrepresentable** (§3 invariant C).
- **Cancellation is a third outcome the write seam must document.** `PRpc::post`
  bridges the synchronous `ureq` POST via `spawn_blocking`; dropping the `submit`
  future (a `timeout`/`select`/shutdown above) **detaches** that task, which runs
  to completion (≤ `GLOBAL_TIMEOUT` ≈ 120 s) and **may still broadcast** the tx
  while the caller gets no value — unlike the principal (hyper) path, which stops
  driving on drop. So the 2c consumer **must not** wrap `submit` in a cancelling
  combinator, or must treat a cancelled submit as ambiguous (same as a returned
  `DaemonAmbiguous`); the reservation's synchronous `in_flight` flip before the
  `await` already yields that retained-ambiguous posture.

---

## 3. Type-enforced invariants (make the bad states unrepresentable)

The enforcement pattern is the SP-T2 mirror; the instances are new.

- **(A) No principal path in — closes *construction*, not the reverse
  direction.** `PTransactionSubmitter` is constructible **only** from a `PRpc`
  (itself constructible only from a `PTorClient`) — no `From<DaemonClient>`, no
  `Default`. A principal `DaemonClient` cannot be coerced into the `P` submitter;
  the type won't take it. Mirrors `PBlockSource` (`block_source.rs`) and the DQ1
  no-principal-path move, write side. **But note the honest scope (as the S1
  sharpening did for (B)):** this makes a *P submitter over the principal
  connection* unrepresentable; it does **not** stop handing `P`'s tx **bytes** to
  the *principal* `DaemonTransactionSubmitter` — the `submit(Vec<u8>)` trait takes
  opaque bytes with no persona binding, so origin-in-`P`-space on the write path
  is **not** structurally closed here. The posture→submitter dispatch that routes
  ②→`PTransactionSubmitter` (never the principal submitter) is the load-bearing
  guard — its **shape is now frozen in §3.1** (closed-set enum, single
  constructor choke point, `PBoundBytes` pairing); the implementation lands in
  2c. "Axis 1 covered" (§2) means *the submitter exists and is principal-path-
  free by construction*, not *the routing is enforced* — the latter lands in 2c.
- **(B) *System-selected* broadcast-③ is unrepresentable — a *different,
  narrower* Posture type — and `OwnRemote` is trust-on-user-assertion.** The
  broadcast posture is **not** the fetch `Posture`. It is a distinct type with
  **`Local` and `OwnRemote` only — no `ThirdParty` variant at all** (not a
  `ThirdParty` arm that returns an error; the variant does not exist). This is
  **stronger** than the fetch selector's no-silent-③ (which allows ③ when
  explicitly named): the broadcast selector is **no-③-at-all**, and a "unify the
  selectors for symmetry" refactor **cannot silently re-enable broadcast-③** — it
  would have to *add the variant back*, a visible, reviewable change.

  **But the forbid closes the *system-selected* path, not the *user-mislabeled*
  one — and that limit is on the record, not papered over.** `OwnRemote {
  base_url }` carries an unconstrained onion, and "is this `base_url` my own node"
  is **not a type-checkable property** — an onion address carries no ownership
  proof the wallet can verify. So a user who puts a **third party's** onion in
  `OwnRemote` (by mistake, or because a stranger's node is convenient) broadcasts
  through a stranger and reopens the exact first-seen-origin leak: the type makes
  ③ unrepresentable to the *system*, but it cannot make a value in `OwnRemote`
  point only at *your* node. So "unrepresentable" is true of the *variant* and
  false of the *leak* — and a genesis reader must not take it as "impossible."
  `OwnRemote` is therefore **trust-on-user-assertion**, carrying a mandated
  **config-point disclosure** (the same disclose-the-cost posture the fetch-③
  path uses): *this must be a node you control; pointing it at a third party
  defeats the broadcast firewall — first-seen-origin is a permanent, categorical
  link.* The only *structural* closure is a **rule-21 reopen**: an
  **authenticated `OwnRemote`** (a client-auth onion / proof-of-ownership) would
  make "my own node" type-checkable — out of scope now, the named path if the
  disclosure proves insufficient.
- **(C) Retry holds the bytes; rebuild-on-retry cannot compile.** The submit
  contract carries the already-built `tx_bytes`; "retry" re-sends the *same held
  bytes*. There is no path where a retry re-derives a tx (new inputs/signature →
  new txid → the double-spend that burns the persona). Idempotency is by
  construction (same bytes → same txid → daemon dedupes), and the ambiguous-
  failure surface is `DaemonAmbiguous`, never a silent auto-rebuild.

The **two-different-selector-types asymmetry** (invariant B) is the genesis-
adjacent firewall stance this doc settles: it is decided once, deliberately, and
must not be re-litigated by a symmetry refactor.

### 3.1 The posture→submitter dispatch shape (FROZEN 2026-07-04, user-ratified)

Invariant (A) left the routing guard as an open obligation and the FOLLOWUPS
dispatch-shape entry posed the API choice (`TransactionSubmitter::submit` is
RPITIT → not dyn-compatible; the two impls share no nameable type). The choice
is now frozen — it gates [`DAEMON_SUBMIT_VERDICT.md`](DAEMON_SUBMIT_VERDICT.md)
PR-4, whose "both submitters share the mapping" presupposes it. Five parts:

1. **Closed-set enum, match-delegation.**
   `BroadcastSubmitter<D> { Local(DaemonTransactionSubmitter<D>),
   PerP(PTransactionSubmitter) }`, implementing `TransactionSubmitter` by
   matching and delegating. Grounds: the broadcast submitter set is *closed by
   type* (invariant B — no ③ variant exists), so the enum states the closed set
   for free, where a boxed `async_trait` or dyn shim would pay allocation to
   erase it. **RPITIT compatibility is verified, not assumed**: a compile probe
   on the workspace MSRV toolchain (1.94.0) over these exact shapes — generic
   arm + concrete arm, `+ Send` bound — compiles clean with `async fn`
   match-delegation, one unified `Send` future, no `Box`.
2. **One construction choke point.** `select_broadcast` stays posture-only (its
   existing contract — it resolves a posture, never a submitter). The enum gains
   the single constructor (posture in, submitter out) in
   `transaction_submitter.rs`, so the posture→submitter binding — the (A)
   routing guard, ②→`PerP` and never the principal submitter — is a property of
   one audited constructor, not a convention at call sites.
3. **Arms.** `Local` wraps the principal's loopback submitter (the wallet's own
   local daemon observing `P`'s tx is conceded — it is the operator's node;
   loopback never crosses the network). `PerP` wraps `PTransactionSubmitter`
   over `P`'s own circuit. The `DaemonUrl` newtype (FOLLOWUPS, 2c config-source
   slice) slots into the `PerP` construction path when it lands.
4. **Byte↔persona pairing: checked at the choke point, not type-branded.** A
   `PBoundBytes { persona, bytes }` newtype is the enum façade's accepted input;
   the constructor-bound persona is equality-checked against it (`debug_assert`
   loud in dev, fail-closed error in release — the `validate_handle`
   discipline). Full per-persona type branding is **rejected for now**: the
   persona set is dynamic, so branding costs const-generic machinery for a
   state the single-constructor path already makes unreachable. Rule-21 reopen:
   a static-persona context (or a second call-site family outside the
   choke point) re-raises branding.
5. **Survives PR-4.** Match-delegation is agnostic to the trait's output shape:
   when `DAEMON_SUBMIT_VERDICT.md` PR-4 reshapes `submit`'s result into the
   `SubmitVerdict` projection (§2.5 dispositions), the enum carries through
   unchanged, and "both submitters share the mapping" is literal — one mapping
   function, two transports, one dispatch type.

Implementation lands with the 2c wiring (the enum + constructor + `PBoundBytes`
are 2c-2a/2c-2b code, PR-4-adjacent); this section freezes the shape so nothing
downstream is built against a different one.

#### 3.1.1 Post-freeze wargame (2026-07-04): byte-holder enumeration — freeze CONFIRMED, two provenance pins added

The freeze above pins the *check* (persona equality at the choke point) but
not the *provenance* (who may mint a `PBoundBytes`, and whether the value
survives the retry lifecycle or gets re-wrapped from raw bytes). The wargame
that surfaces the gap: **enumerate every holder of persona-bound `Vec<u8>`
that can reach a `submit`** — each is a site where "these bytes" and "this
circuit" must be provably the same persona.

| Holder | Site | Mis-pairing exposure under §3.1 as frozen |
| --- | --- | --- |
| **H1 — assemble/sign path** | `StakeEngine` (`stake_engine.rs`): `sign_bond` → `build_join_market_vin` composition — the only site that *knows* which persona's slot keys signed the bytes | **Closed.** Bytes are born here; wrapping at birth carries ground truth. Choke-point equality check + enum exhaustiveness make both mis-pairings (`P1`→`P2`-circuit; persona→principal) unreachable. |
| **H2 — F31 status-query resubmit** | resubmit-same-bytes from the held record — today `local_pending_tx.rs:204` stores `tx_bytes: Vec<u8>`, persona-unbound | **Open as frozen.** If the held record stores raw bytes, the resubmit path must *re-wrap* them into a `PBoundBytes` at probe time — and the choke-point check then validates the **wrapper's claim**, not the bytes' provenance. A re-wrap site that attaches the wrong persona (or routes to `Local`) passes every §3.1 check. |
| **H3 — watchdog resubmit rung** | `submit_watchdog.rs` `ProbeResubmitSameBytes` — the kernel decides the probe; the driving actor re-sends the held bytes | **Same exposure as H2** (it executes H2's re-send). The ladder's privacy-neutrality claim ("identical bytes, same txid") is about the *network* artifact; it says nothing about which *circuit* carries the probe — a probe for `P`'s tx sent over the principal connection is precisely the first-seen-origin correlation the firewall exists to prevent, now on the retry axis instead of the first-send axis. |

The exposure at H2/H3 is not a flaw in the frozen shape — the enum, choke
point, and equality check are all correct — it is a **provenance hole
beside it**: the check trusts the newtype, so the newtype must be
unforgeable-by-construction and must **travel**, not be reconstructed. Two
pins close it, both freeze-compatible (they constrain implementation; they
do not alter the frozen shape):

1. **P-1 — mint-site pin.** `PBoundBytes` has exactly one constructor,
   private to the assemble/sign module (`pub(super)`-or-tighter; no public
   `new`, no `From<(PersonaHandle, Vec<u8>)>`). It is minted at the moment
   the bytes are signed under the persona's slot keys — the one site where
   the pairing is ground truth rather than a claim. Everywhere else in the
   codebase, a `PBoundBytes` can be *held* or *moved* but never *created*,
   so possession is proof of provenance (the same possession-is-proof shape
   as the `sign_bond` by-value token, §"contract #1" in `stake_engine.rs`).
2. **P-2 — carry-through pin.** The held/pending record for a `P`-bound tx
   stores the **`PBoundBytes` value itself**, not `Vec<u8>` (the principal
   tx's held record keeps raw bytes as today — the type distinction is the
   routing fact and must persist through the retry lifecycle). F31 and
   watchdog resubmits re-send the *stored* value through the same §3.1
   choke path as the first send; no re-wrap site exists anywhere.
   Consequence: "which submitter does the probe use" is answered by the
   stored type, never re-derived at probe time — H2 and H3 collapse into
   H1's already-closed case.

**Outcome: freeze confirmed, no reopen.** `Box<dyn TransactionSubmitter>`
re-examined against the enumeration and rejected on the same grounds,
strengthened: erasure discards the persona discriminant exactly where H2/H3
need it. The rule-21 branding reopen recorded in §3.1(4) is **unchanged** —
P-1/P-2 are not branding (the persona id stays a runtime value); they close
the wrapper-forgery hole at the module boundary instead, which is the cheap
point on the same curve. The pins are implementation obligations for the 2c
wiring slices (2c-2a assemble wiring mints per P-1; the 2c submit-consumer /
watchdog slice persists per P-2).

---

## 4. The GF-7 disclosure — a genesis gate, not a deferred round (loud)

The honest core of SP-T4a's threat model: **the timing axis the firewall most
needs closed is unmeasured.** GATE6 §10.12 records it — S-1 (funding/exit seams
are the only findings protecting principal↔`P` unlinkability, and the least-
developed because cross-layer, deferred R3/R4); S-3 (the privacy side has *zero*
simulated scenarios; the named residual — funding-seam timing-correlation — is
exactly the `P(link | T_obs)` class that must be measured against a modeled
observer, and has not been).

SP-T4a therefore states plainly, in the design and in code comments at the wire
site:

> SP-T4a *draws* the narrow funding-seam decorrelation (`draw_entry_gap`) but does
> **not** wire it into any broadcast — that wiring (and the scheduler that carries
> both the `_spread` delay and the `_bond_first` order-coin to the wire) is
> **2c-2a/2c-2b**. Even once wired, it does **not** decorrelate `P`'s broadcast
> from the principal's lifecycle timeline (GF-7), nor from `P`'s other broadcasts.
> That correlation is **deferred (GATE6 R3/R4) and unmeasured (S-3)** — out of this
> slice's scope, and only *becomes measurable* once 2c builds the real consumer.
> GF-7's measurement round inherits: (i) the standoff window
> (`DEFAULT_ENTRY_GAP_WINDOW = 600`) as the parameter to grade `P(link | T_obs)`
> against; (ii) the entry/bond-post as the broadcast the jitter is *drawn for*
> (wiring pending 2c); (iii) the open question of principal-timeline and
> cross-broadcast decorrelation, which no built primitive addresses and which 2c's
> scheduler is the only home to mitigate.

This is a **named, deferred residual with a disclosed inheritance**, not a silent
gap — the `21-reversion-clause-discipline` / disclosed-cost posture.

**GF-7 is a genesis gate, not merely a deferred round.** §4's own framing — *the
timing axis the firewall most needs closed is unmeasured* — is the reason:
everything here is pre-genesis, and shipping the broadcast seam with the
principal↔`P` timing correlation unmeasured would launch the write-side firewall
**unvalidated on its core axis** — exactly what *get-it-right-not-get-it-now*
forbids for a privacy coin's firewall (`00-mission` #2). So the residual carries
an explicit launch condition, not just an inheritance: **genesis cannot ship
until GF-7's `P(link | T_obs)` is measured against a modeled observer and meets
threshold** (the S-3 privacy-sim obligation on the funding/exit timing seams).
That elevates GF-7 from "a round someone will get to" to "the thing that blocks
launch" — its correct weight — and prevents the failure mode where a disclosed-
but-unweighted residual quietly slips past genesis. Tracked as a genesis blocker
in `docs/FOLLOWUPS.md`.

---

## 5. Decomposition (commit-slices — one PR unless it grows exceptionally large)

One validation surface (the `P`-broadcast seam + its enforcement), clean
per-surface commits (the #238 shape):

1. **Shared submit-verdict mapping.** Extract the `TxRelayResponse →
   TxSubmitOutcome` mapping (currently `DaemonClient`-side, `daemon.rs:142`) into
   a shared helper both the principal and `P` submitters use — the P9-style
   dedup enabler (no behavior change, principal path identical).
2. **`PTransactionSubmitter` (the CX-2 write-side seam).** Implements
   `TransactionSubmitter`, constructed only from `PRpc`/`PTorClient` (invariant
   A); maps any transport error → `DaemonAmbiguous` (axis 4, never `classify`'s
   retryability); ships with its proving test — a dead SOCKS proxy →
   `DaemonAmbiguous`, SOCKS username never rendered (mirror `PBlockSource`'s
   dead-proxy test; invariant (a)).
3. **Broadcast `Posture` + selector (no-③-at-all).** A distinct type with
   `Local`/`OwnRemote` only (invariant B); the selector refuses to resolve a
   third-party broadcast because it *cannot represent one*. Proving test: the
   type has no `ThirdParty` constructor (a compile-fenced absence) + the selector
   *refuses* to yield ③ (the exhaustive-match fence test). **Note:** slice 3 ships
   the posture *decision* only — `select_broadcast` returns a `BroadcastPosture`,
   **not** a submitter. The posture→submitter dispatch (①→principal,
   ②→`PTransactionSubmitter`) is **2c-2b's** obligation, not shipped or tested
   here (it needs a dispatch shape the RPITIT trait can't express as-is — see the
   2c tracked obligation). Do not read this slice as proving the routing.
4. **Point the consumer at the seam (production wiring is *gated*).** The real
   end-consumer — the discretionary `JoinMarketVin` bond-post — **cannot** be
   wired end-to-end yet, and verifying-at-source is why: `JoinMarketVin` is a tx
   *input* (it needs funding inputs/outputs + `credit_term` →
   `sign_transaction_with_terms` to assemble a submittable tx), and `StakeEngine`
   holds no broadcast submitter / posture / block-timed scheduler — it is inert
   pending the 2c-2a assemble / 2c-2b request-path wiring. That is a real
   dependency (defer-only-on-a-real-blocker), not a shrink-the-PR defer. So slice
   4 updates the `TODO(2d)` (in `stake_engine.rs`) to point at the built seam
   and name exactly what production wiring still needs, and records the GF-7 scope
   (§4) at the timing-draw site — a comment at the consumer site, **not**
   production wiring. The seam ships now as the **prerequisite** that 2c-2a/2c-2b
   will consume: a byte-defined-consumer building block, fully tested by slice 2's
   proving test — not consumer-less infra (contrast SP-T3, whose onion had no
   byte-defined payload at all).
5. **Docs (rule 91).** This doc (incl. the S1 *trust-on-user-assertion*
   sharpening on `OwnRemote` and the S2 *GF-7 genesis-gate* elevation); refine
   `TRANSPORT_PLAN.md` §15 SP-T4 to point here and record the broadcast-③ forbid
   + selector asymmetry; **fix the stale line-ref** at `TRANSPORT_PLAN.md:94`
   (point it at the `TODO(2d)` in `stake_engine.rs`, no fragile line number); add
   the GF-7 genesis-blocker entry to `docs/FOLLOWUPS.md`.

**SP-T4b** (serve-credit challenge-response broadcast) is the separate, gated
follow-up — it reuses this seam once a GATE2 wallet-side build/sign/submit
producer for `ArchivalServeCreditResponse` exists.

---

## 6. Posture read-model (broadcast axis — for the transport plan)

| Posture | Fetch (SP-T2 §5) | Broadcast (SP-T4a) |
| --- | --- | --- |
| ① Local | direct localhost source | direct localhost submit (own node) |
| ② Own-remote | `PBlockSource` over `P`'s circuit | `PTransactionSubmitter` over `P`'s circuit |
| ③ Third-party | **allowed, disclosed** (continuous · statistical · unavoidable) | **forbidden by type** — no ③ variant (discrete · categorical · avoidable; first-seen-origin). *System-selected* ③ unrepresentable; an `OwnRemote` pointed at a stranger is the disclosed residual (invariant B). |

**Read/write asymmetry on ① when unreachable.** `select_broadcast` (like the fetch
`select`) *honors* an explicitly-named `Local` even when the reachability probe
says the node is down — the named choice is authoritative. On the **read** path a
dead local node then surfaces as a per-fetch error and the scan stalls. On the
**write** path the same dead node turns *every* broadcast into a `DaemonAmbiguous`
(§2 axis 4) that, with no TTL exit, wedges the reservation's output locks until
wallet restart — so "a dead node surfaces as an error" is materially heavier for
broadcast. The clean pre-flight refusal exists only on the no-choice arm; making a
dead-local broadcast a loud refusal rather than a lock wedge is part of 2c's
submit-outcome-partition obligation (below).

The ③ column is the whole point: the selectors differ because the operations'
threat models differ, and the difference is encoded in **two distinct types**.
