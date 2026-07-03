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
  posture-selector, **proven by wiring the one real, already-built consumer:**
  the discretionary `_spread`/`_bond_first` entry/bond-post broadcast. The bond
  vin is built + signed today (`build_join_market_vin`), the anchor-free timing
  draw exists (`draw_entry_gap_guarded`), and only the submission is deferred
  (`TODO(2d)`, `stake_engine.rs:1095`). SP-T4a fleshes exactly that out — so the
  seam ships with a real consumer, not consumer-less infrastructure (the SP-0 /
  SP-T2 bar).
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
  method over `post`, `shekyl-rpc-client/src/lib.rs:491` → `send_raw_transaction`
  → `TxRelayResponse`). A tx broadcast over `P`'s own circuit is callable today
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
  daemon dedupes by hash → `TxSubmitOutcome::AlreadyKnown`; the path **never
  rebuilds on retry**.
- **The real consumer.** `build_join_market_vin` returns a signed `JoinMarketVin`
  (`stake_engine.rs:1109`); `draw_entry_gap_guarded` returns `(_spread,
  _bond_first)` (`:1089`); the submission is the open `TODO(2d)` (`:1095`).
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
- **What SP-T4a does.** Wire `draw_entry_gap`'s `(_spread, _bond_first)` into the
  entry/bond-post submission (the `TODO(2d)`). This applies the built primitive
  to the one broadcast it was designed for.
- **What SP-T4a explicitly does NOT close (the GF-7 residual — §4).** The
  broader **principal-timeline** correlation (does `P`'s broadcast timing track
  the principal's lifecycle activity?) is **GF-7**, which GATE6 §10.12 flags
  (S-1) as *the* load-bearing principal↔`P` unlinkability seam **and** the
  least-developed, still **deferred (R3/R4)**, and (S-3) **unmeasured** — no
  `P(link | T_obs)` simulation exists. SP-T4a **must not claim the timing axis
  closed.** It wires the narrow funding-seam primitive and hands GF-7 forward as
  a named, deferred, measured-someday residual (§4).

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

### Axis 4 — ambiguous partial-failure (**new — but the principal contract already solves it**)

A `ConnectionError` on submit does **not** tell you whether the tx propagated —
the daemon may have accepted and relayed it before the response failed. So
"retry on `ConnectionError`" — correct for fetch, and what `PRpc`'s fetch-style
`classify` would hand you — is **wrong** for broadcast if it means "re-derive and
re-submit." The principal path already has the right contract (§1); SP-T4a's job
is to **carry it onto the `P` path, not inherit `PRpc`'s fetch `classify`:**

- `PTransactionSubmitter::submit` maps **any** `Err` from `publish_transaction`
  to `SubmitError::DaemonAmbiguous` — exactly as `DaemonTransactionSubmitter`
  does (`transaction_submitter.rs:68`). It **does not consult `classify`'s
  transient/permanent verdict** to decide a local retry: absence-of-verdict is
  ambiguous, full stop.
- Retry (with dedup) belongs to the **orchestrator**, which re-submits the
  **same held bytes** → same txid → daemon dedupes → `AlreadyKnown`. Retry =
  re-send the same bytes; **rebuild-on-retry is unrepresentable** (§3 invariant
  C).

---

## 3. Type-enforced invariants (make the bad states unrepresentable)

The enforcement pattern is the SP-T2 mirror; the instances are new.

- **(A) No principal path in.** `PTransactionSubmitter` is constructible
  **only** from a `PRpc` (itself constructible only from a `PTorClient`) — no
  `From<DaemonClient>`, no `Default`. A principal `DaemonClient` cannot be
  coerced into the `P` submitter; the type won't take it. Mirrors `PBlockSource`
  (`block_source.rs:196`) and the DQ1 no-principal-path move, write side.
- **(B) Broadcast-③ is unrepresentable — a *different, narrower* Posture type.**
  The broadcast posture is **not** the fetch `Posture`. It is a distinct type
  with **`Local` and `OwnRemote` only — no `ThirdParty` variant at all** (not a
  `ThirdParty` arm that returns an error; the variant does not exist). This is
  **stronger** than the fetch selector's no-silent-③ (which allows ③ when
  explicitly named): the broadcast selector is **no-③-at-all**. Because it is
  encoded in the type, a future "unify the selectors for symmetry" refactor
  **cannot silently re-enable broadcast-③** — it would have to *add the variant
  back*, a visible, reviewable, reason-demanding change. The two selectors are
  deliberately different types; that difference **is** the recorded decision.
- **(C) Retry holds the bytes; rebuild-on-retry cannot compile.** The submit
  contract carries the already-built `tx_bytes`; "retry" re-sends the *same held
  bytes*. There is no path where a retry re-derives a tx (new inputs/signature →
  new txid → the double-spend that burns the persona). Idempotency is by
  construction (same bytes → same txid → daemon dedupes), and the ambiguous-
  failure surface is `DaemonAmbiguous`, never a silent auto-rebuild.

The **two-different-selector-types asymmetry** (invariant B) is the genesis-
adjacent firewall stance this doc settles: it is decided once, deliberately, and
must not be re-litigated by a symmetry refactor.

---

## 4. The GF-7 disclosure (loud — what remains open and why it is out of scope)

The honest core of SP-T4a's threat model: **the timing axis the firewall most
needs closed is unmeasured.** GATE6 §10.12 records it — S-1 (funding/exit seams
are the only findings protecting principal↔`P` unlinkability, and the least-
developed because cross-layer, deferred R3/R4); S-3 (the privacy side has *zero*
simulated scenarios; the named residual — funding-seam timing-correlation — is
exactly the `P(link | T_obs)` class that must be measured against a modeled
observer, and has not been).

SP-T4a therefore states plainly, in the design and in code comments at the wire
site:

> SP-T4a wires the narrow funding-seam decorrelation (`draw_entry_gap`) into the
> entry/bond-post broadcast. It does **not** decorrelate `P`'s broadcast from the
> principal's lifecycle timeline (GF-7), nor from `P`'s other broadcasts. That
> correlation is **deferred (GATE6 R3/R4) and unmeasured (S-3)** — out of this
> slice's scope. GF-7's measurement round inherits: (i) the standoff window
> (`DEFAULT_ENTRY_GAP_WINDOW = 600`) as the parameter to grade `P(link | T_obs)`
> against; (ii) the entry/bond-post as the one broadcast currently jittered;
> (iii) the open question of principal-timeline and cross-broadcast
> decorrelation, which no built primitive addresses.

This is a **named, deferred residual with a disclosed inheritance**, not a silent
gap — the `21-reversion-clause-discipline` / disclosed-cost posture.

---

## 5. Decomposition (commit-slices — one PR unless it grows exceptionally large)

One validation surface (the `P`-broadcast seam + its enforcement + its real
consumer), clean per-surface commits (the #238 shape):

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
   maps ①→principal submitter, ②→`PTransactionSubmitter`, and there is no ③ arm.
4. **Wire the real consumer.** Replace the `TODO(2d)` (`stake_engine.rs:1095`):
   route the signed `JoinMarketVin` through the `P`-broadcast seam, timed by
   `(_spread, _bond_first)`, with the GF-7 disclosure comment (§4) at the wire
   site. This is the consumer that proves slices 2–3.
5. **Docs (rule 91).** This doc; refine `TRANSPORT_PLAN.md` §15 SP-T4 to point
   here and record the broadcast-③ forbid + selector asymmetry; **fix the stale
   line-ref** at `TRANSPORT_PLAN.md:94` (`stake_engine.rs:956-962` →
   `:1089-1096`).

**SP-T4b** (serve-credit challenge-response broadcast) is the separate, gated
follow-up — it reuses this seam once a GATE2 wallet-side build/sign/submit
producer for `ArchivalServeCreditResponse` exists.

---

## 6. Posture read-model (broadcast axis — for the transport plan)

| Posture | Fetch (SP-T2 §5) | Broadcast (SP-T4a) |
| --- | --- | --- |
| ① Local | direct localhost source | direct localhost submit (own node) |
| ② Own-remote | `PBlockSource` over `P`'s circuit | `PTransactionSubmitter` over `P`'s circuit |
| ③ Third-party | **allowed, disclosed** (continuous · statistical · unavoidable) | **forbidden — unrepresentable** (discrete · categorical · avoidable; first-seen-origin) |

The ③ column is the whole point: the selectors differ because the operations'
threat models differ, and the difference is encoded in **two distinct types**.
