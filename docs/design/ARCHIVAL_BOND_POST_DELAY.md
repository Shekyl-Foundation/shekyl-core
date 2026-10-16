# Bond-post delay — what it decorrelates: Round 0

**Status:** OPEN — Round 0, questions **POSED 2026-10-15**; nothing is
ruled. Each question carries a default, its reason, what the alternative
changes, and a falsifier. **No code until the questions are ruled**
([`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)).

**Ground:** `shekyl-core` `dev` at `d26148535` (the #1078 merge). Every
`file:line` below was read at that commit. Paths under `engine/` are in
`rust/shekyl-engine-core/src/engine/`.

**Identifier family:** `BD-Q1…BD-Q5` (the questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth.

**Sequencing:** the round rules **before `DEL-008`**
([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §12). That deletion is when
the Rust daemon starts accepting bond posts and the defect goes live.
Until then the C++ daemon refuses every kind-5 JoinMarket post before any
reference check, which hides it. The deadline binds BD-Q3. The window
(BD-Q4) can be argued after BD-Q3 is ruled (§1.2). The wallet-RPC round
([`WALLET_RPC_STAKING_OUTCOMES.md`](WALLET_RPC_STAKING_OUTCOMES.md), PR
#1079) proceeds in parallel; §6 lists what passes between them.

**The design intent (Rick, 2026-10-15):** the delay jitters the bond
funding appearing on chain against the archival bond appearing, so the
bonded `P` service is hard to connect to its funding transaction.

---

## 1. The defect

### 1.1 What the code does

| Fact | Where |
| --- | --- |
| The principal funds `P` with an ordinary FCMP++ transfer, `stake_in`, a separate transaction before the stake request. | `engine/principal_stake.rs:153-158` |
| The stake request (`first_stake`) sweeps `P`'s funding outputs that the P-scan has found, persists the bonded slot, then assembles and signs the post. It does not broadcast. | `engine/bond_orchestrator.rs:833`, `:975-1004`; doc `:803-809` |
| A funding output can be swept only once its leaf is in the tree at the reference height: `spendable_height ≤ reference_height`. | `engine/backing_set.rs:156` |
| `spendable_height = height + SPENDABLE_AGE` (10) for an ordinary output. | `shekyl-engine-state/src/transfer.rs:33-34`, `:65-71`; `shekyl-consensus/src/lib.rs:28` |
| The wallet records the funding output's block height and its spendable height. | `shekyl-engine-state/src/pscan_state.rs:237`, `:259` |
| The delay is drawn at the request: `bond_post_offset_blocks ~ U[0, 600]`, one unbiased draw. | `engine/stake_engine/actor.rs:154-170`; `shekyl-standoff/src/draw.rs:96-98` |
| `anchor_t0` is the daemon-claimed tip at the request. The reference is `min(synced tip, ingested tip) − REF_ANCHOR_AGE` (6). | `engine/bond_orchestrator.rs:443-461`, `:555-557` |
| The signed bytes are sealed with `anchor_t0` and the offset; `due = anchor_t0 + offset`. | `engine/bond_orchestrator.rs:662-670`; `engine/pscan/dispatch.rs:265-272` |
| Every send, first or retry, re-sends the sealed bytes. | `engine/pscan/dispatch.rs:763-769`; `ARCHIVAL_BOND_WI3_DISPATCH.md:328-329` (§3.6: "never re-drawn for existing bytes") |
| A reference older than `MAX_AGE` (100) is refused. A proof built at the canonical anchor is submittable for `PROOF_VALIDITY_HORIZON` (94) blocks. | `shekyl-curve-tree/src/reference.rs:95-106`; `shekyl-chain-rules/src/rules/tx_against.rs:320-324` |
| `REF_ANCHOR_AGE` is privacy-canonical, so "the on-wire reference age does not fingerprint the wallet". | `shekyl-curve-tree/src/reference.rs:75-84` |
| The Rust daemon answers a too-old reference `StaleRoot`; the wallet classes it retryable and resends the same bytes until the 900-block alarm. | `shekyl-daemon-rpc/src/submit/engine.rs:374`; `engine/transaction_submitter.rs:270`; `engine/pscan/dispatch.rs:213-216`, `:825-831` |
| `600` is a self-declared provisional sentinel; its multi-event derivation is void. | `shekyl-standoff/src/draw.rs:71-80`; `ARCHIVAL_BOND_WI4_MEASUREMENT.md` §13.1, `:796-806` |
| `MIN_COLD_START_SPACING` (one settlement epoch between funding and bond) is `#[allow(dead_code)]`, "inert until cold-start spacing check is wired". | `engine/stake_timing.rs:192-203` |

### 1.2 What follows

- **Most posts never land.** An offset over 94 sends a reference already
  past the window: 506 of the 601 equally likely offsets, about 84 %.
  Each is resent unchanged until the alarm. The ignored test
  `a_bond_post_sent_past_its_proof_lifetime_is_resent_unchanged_to_the_horizon`
  on #1079 (`engine/pscan/dispatch_tests.rs`) shows it.
- **The post shows when it was signed.** A post sent `offset` blocks after
  signing carries reference age `offset + 6`. Any node can subtract and
  recover the request height. The delay hides nothing about the event it
  is measured from.
- **For a staker who stakes as soon as funding allows, the reference
  points at the funding block.** The earliest request is at tip
  `h_f + 16`, where `h_f` is the funding output's block:
  `spendable_height = h_f + 10` must be at or below `tip − 6`. That post's
  reference height is `h_f + 10`, so `reference − SPENDABLE_AGE = h_f`
  whatever the offset. A chain-only observer reads the funding block off
  the bond post.
- **The delay is measured from the wrong event.** The intent is to
  separate the bond from the funding. The draw starts at the request,
  which is a private moment, and the guard that measures from funding is
  unwired.

The defect and the cover question are separable. **Signing at the due
time (BD-Q3) removes the dead posts and the reference leak whatever the
window is.** BD-Q1, BD-Q2 and BD-Q4 decide how much cover the delay buys;
BD-Q5 removes the dead constant either way.

---

## 2. What the posture says today

- **Method note 8** counts events on the chain, not in the pipeline. An
  event counts only if an observer can see it as distinct; the funding
  transfer is "not attributable, therefore not an anchor". The pipeline
  "is invisible to every observer the posture admits"
  (`ARCHIVAL_FIREWALL_GATE6.md:2212-2233`; pass-4 (d) closure `:1589-1617`).
- **The WI-4 retraction** keeps the spread for one adversary only: "live
  defense-in-depth only against an off-chain-anchored adversary — someone
  who knows the principal and saw them act at time `T` — and dead against
  the chain observer". It freezes the rule for `600`: it re-derives only on
  "(a) a measurable off-chain anchor-precision model arriving, or (b) a
  pure cost-side (latency) decision", and calls that anchor precision
  "unquantifiable in principle" (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:776-806`).
- **The gate's threat table admits network observers**: "Local / ISP"
  (principal clearnet link timing) and "Partial passive (GPA-lite)"
  (`ARCHIVAL_FIREWALL_GATE6.md:1036-1050`).
- **The principal side is clearnet by default.** "Until it lands, a
  passive network observer needs *no user error* to correlate principal
  daemon traffic with on-chain events — the vantage is granted by our
  default" (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:4072-4086`); the default flip
  is "NOT YET BUILT" (`:1988`).
- **Dandelion++ does not cover the first edge.** A wallet submission stems
  from the daemon that accepts it (`DAEMON_RELAY_PRIVACY.md:796-805`), and
  stem-and-fluff "does not hide the origin from a passive observer that
  already sees the first stem edge" (`:1238`).

---

## 3. Questions

### BD-Q1 — Which observers does the posture admit for the funding event?

**Default: three observers, each with a named anchor and channel.** For
two of them the funding transfer is an event, so method note 8 is scoped
to the chain observer.

| Observer | What it sees (`T` and its channel) | Anchor precision |
| --- | --- | --- |
| **Chain-only** | The bond post, which names `P`. The funding transfer is an unattributable FCMP++ transfer. | None after BD-Q3. Today the reference age gives it the request height, and for an instant staker the funding block (§1.2). |
| **Network origin** of the principal's transfer: the ISP or first stem edge of the principal's node, a GPA-lite relay fraction, or the remote daemon and its link when the wallet does not use its own node | The funding transaction leaving the principal. It learns the transaction's hash and so its block. | One block. |
| **Funding counterparty**: whoever delivered the coins the principal funds `P` with (the "on-ramp witness", `ARCHIVAL_BOND_WI4_MEASUREMENT.md:4097-4099`) | Its own delivery to the principal. "The chain goes dark to the counterparty too": it does not see the principal's later transfer to `P`. | Coarse, set by the principal's own behaviour between receiving and funding. It reaches block precision only if it also holds the network-origin position. |

**Reason.** The reopening uses note 8's own test. "An event counts only if
an observer can see it as distinct", and "asking *which observer* names
the excluded posture". The network-origin observer sees the funding
transfer as distinct: it watched it leave the principal. The gate already
admits that observer (§10.1's Local/ISP and GPA-lite rows), and our
default grants it (WI-4 trace 1). Note 8's "invisible to every observer
the posture admits" holds for the chain observer and fails for the first
stem edge. The intent names this observer: someone who sees the funding
appear and wants to find the bond. This is also WI-4's trigger (a). The
off-chain anchor is not unquantifiable for this observer: its precision
is one block, which is what BD-Q4 consumes.

Two things do not reopen. The order coin stays retired, because the chain
still carries one attributable event and the delay is a jitter against
the funding anchor, not a permutation. Note 8 keeps its force for the
chain observer, against which the delay is still dead.

**What the alternative changes.** Chain-only (note 8 as written): the
delay protects nobody, the window should be zero, and the design intent
is void. Adding the counterparty without the network-origin observer
gives a coarse anchor that any window helps against, so it is not a
sizing input. Leaving out the network-origin observer contradicts §10.1
and the shipped default.

**Falsifier.** The principal's funding transfer reaches the network with
its origin hidden from the first edge by default: the principal-side Tor
flip covers the node's own P2P broadcast, not only the wallet→daemon link.
The network-origin row then becomes opt-out residue rather than a default
vantage. That would not remove it: a user who opts out keeps it, and see
BD-Q4 on why the window is not shrunk afterwards.

**To rule:** if ruled, `ARCHIVAL_FIREWALL_GATE6.md` method note 8 gains a
scoping sentence (the chain observer), and the WI-4 §13.1 banner's
"unquantifiable" names the network-origin observer as the measurable case.
Neither is edited before the ruling.

### BD-Q2 — What is the delay measured from?

**Default: the first height at which the funding can be spent into a
bond. Elapsed time counts, and no fresh draw is added.**

- The **anchor** `a = spendable_height + REF_ANCHOR_AGE` of the reserved
  funding output with the greatest `spendable_height`. For an ordinary
  output that is `h_f + 16`, the earliest height a bond spending it can be
  signed. The wallet knows `spendable_height` from its own record
  (`pscan_state.rs:259`).
- The **draw** `s ~ U[0, W]`, taken once at the request and persisted.
- **`due = max(a + s, the request's tick)`.** If `a + s` has already passed
  at the request, the post goes at the next tick.

**Reason.**

- **The anchor is the event the observer holds.** The network-origin
  observer anchors at the funding block, and the request is private (with
  BD-Q3 nothing is emitted at the request). A delay measured from the
  request adds the principal's reaction time to the delay. The observer
  does not know that reaction time, but it is not wallet-controlled, and
  the common case, staking as soon as allowed, makes it a constant.
- **`+16` is a constant, so it buys nothing.** Every wallet shares
  `SPENDABLE_AGE + REF_ANCHOR_AGE`, so the observer subtracts it. Measuring
  from `a` rather than `h_f` keeps the whole window drawn. With `h_f + s`
  instead, every draw below 16 collapses onto `h_f + 16`, a point mass at a
  public offset from the observer's anchor.
- **Elapsed time counts.** For a request made at elapsed age `e` past `a`,
  the post lands at `a + max(e, s)`. What the observer sees of
  `post − a` is uniform over `(e, W]` with a point mass at `e`. `e` is the
  principal's private choice, so the point mass falls at a place the
  observer cannot name. Adding a fresh draw (`due = request + s`) changes
  nothing the observer can use and turns every late request into up to `W`
  more blocks of latency (rule 82).
- **The greatest `spendable_height` governs a multi-input bond** (the
  logged exception, `engine/bond_orchestrator.rs:581-586`). The window must
  cover the last funding transfer the observer may hold. Earlier transfers
  are then separated by more than the window.

**Wargame: a stake made the instant funding confirms.** The request comes
at `a = h_f + 16` (`e = 0`).

- **Today:** the post is signed at `a` with reference `h_f + 10` and sent
  at `a + s`. Its reference age `s + 6` gives away `a`, and so `h_f`. The
  network observer's link is exact whatever `s` is, and the chain observer
  learns the funding block.
- **Under this default:** the post lands at `a + s`, signed then, with
  reference age 6. The observer's candidates are every bond post in
  `[a, a + W]`.
- **The request anchor with signing at due** (BD-Q3 without BD-Q2) gives
  the same result in this case, because the request is at `a`. The two
  anchors differ only for late requests, where the request anchor adds
  latency and no cover. So BD-Q2's privacy weight rests on BD-Q3. Its own
  contribution is the latency of late stakes and the precise anchor
  definition.

**Two decisions inside this question:**

1. **The clock.** The due check runs on the daemon-claimed count clock,
   and `block_source.rs:179-182` forbids the synced and ingested *tip*
   clocks from feeding `anchor_t0`. A funding record's `spendable_height`
   is a block's height, a chain fact, not a tip clock. Default: `a` is
   computed from the record (count = height + 1) and compared on the
   daemon-claimed clock.
2. **Persist the draw, not the due.** `a` is read from the live funding
   record at each tick, so a reorg that moves the funding output moves the
   anchor with it. Re-drawing `s` after a restart is refused: a second
   sample biases the post earlier.

**What the alternative changes.** The request anchor keeps today's
latency for late stakes and leaves the window's meaning dependent on
when the user clicks. The `h_f` anchor creates the point mass above. The
least-spendable output under-delays the newest transfer in a multi-input
bond.

**Falsifier.** An observer who can see the request instant. Examples: a
remote daemon receiving the request's round trips (`get_fee_estimates`,
the claimed tip, `bond_orchestrator.rs:555-557`, `:958-962`), or a GUI or
wallet RPC host across a network. That observer holds the request as an
anchor, and "no fresh draw" leaves a late post at the request instant.
Under the own-node posture these hops are loopback and the observer does
not exist.

### BD-Q3 — Is the post signed at its due time?

**Default: yes. The request seals an unsigned plan; at the due tick the
actor assembles, proves and signs the post with a fresh reference at the
canonical age. The plan is sealed as signed bytes before the first send.**

**Reason.** Signing at the due time makes the reference age at broadcast
the standard 6. That removes the reference leak (§1.2) and the dead posts
together: a post signed at due is submittable for the full 94-block
horizon from its first send.

**The precedent, as the code has it.** `CB-2` is "no master-seed
re-borrow" (`EMISSION_CLAIM_BUILDER.md:307-309`, `:927-928`), not a
re-derivation from the seed at signing time.

- The seed is borrowed at wallet open. The derive-forward slots, the
  bonded ones included, are derived into bundles there, and the actor
  receives the bundles only (`engine/lifecycle/assemble.rs:357`, `:443`,
  `:454`, `:482`).
- The claim path signs from the held bundle (`engine/stake_engine/claim.rs:160-167`,
  `:498-499`). It re-derives each spent output's secrets from the stored
  `(ciphertext, index)` inside the actor at assembly time
  (`engine/stake_engine/helpers.rs:257-272`). The bond handler borrows the
  held bundle the same way (`engine/stake_engine/bond.rs:103-108`).
- `P`'s keys are deterministic in `(master_seed, network, format, p_slot)`
  (`shekyl-crypto-pq/src/archival_p.rs:18-20`). `persist_bond_record`
  writes the slot into `bonded_slots` at the request, so every later open
  re-derives it.
- `PlanBondPost` already plans without signing
  (`engine/stake_engine/persona.rs:402-404`, `:461-470`) and has no
  production caller (`engine/stake_engine/handle.rs:342`). It is the shape
  of the planning half.

Signing at due therefore holds no new secret: the bundle is in the actor
whenever the wallet is open, and no secret is persisted.

**What a pending stake holds before it is signed:**

| Held | Why | Today |
| --- | --- | --- |
| `p_slot` | Names the persona the actor signs for. | Held. |
| The reservation, `funding_gindexes` | Keeps the cadence driver's claims and drains off the funding until the bond spends it. `reserved_gindexes()` already unions it (`shekyl-engine-state/src/pending_post_block.rs:536-555`). | Held. |
| The draw `s` (BD-Q2) | The due is `a + s`. A re-draw is refused. | `bond_post_offset_blocks` |
| The holdings descriptor (the posture) | Assembly moves to the due tick, and the posture is the caller's. Today "nothing posture-shaped is persisted" (`engine/bond_orchestrator.rs:827`) because the posture is consumed at once. | Not held. New. |
| Not the fee | Estimated at the due tick from the daemon's live estimate, as `first_stake` does now (`engine/bond_orchestrator.rs:958-962`). | — |
| Not the tx bytes, the reference or the key image | Produced at the due tick. | `tx_bytes` |

That is a persisted-schema change: a planned state (or kind) in the
pending-post block, the posture added, `anchor_t0` replaced by the anchor
rule. `PENDING_POST_VERSION` (12, `pending_post_block.rs:94`) bumps under
rule 42 with its snapshot (`shekyl-engine-state/schemas/pending_post_block.snap`).
A mismatched seal fails closed, as today (`:91-93`).

**The states.** W1 (preflight, nothing durable) and W2 (`bonded_slots`
written, no record) stay. The new **planned** state (durable plan and
reservation, no signature) comes before **signed** (bytes sealed,
`Pending`), then `Dispatched`.

**Surviving a restart.** The plan reloads with the pending block. The
bonded slot is re-derived at open. At the first tick at or past due, the
driver has the engine assemble, then seals the signed bytes, then sends.
A wallet closed at due posts on the first tick after reopening; the post
is signed then and valid, where today's sealed bytes would be dead.

**After signing.** Retries resend the same bytes while the reference is
young. At `REBUILD_AT` (50, `reference.rs:116`; `should_reanchor`, `:249`)
the post is re-signed with a fresh reference, as the ordinary send path
re-anchors. The same inputs give the same key images, so at most one
version lands. `StaleRoot` then means "re-sign", not "resend".

**What changes for WI-3.** The dispatch driver "never constructs or
signs" (`ARCHIVAL_BOND_WI3_DISPATCH.md:34-35`). Under this default it
triggers assembly through the engine at due. The single-writer seal
discipline (§3.3) and seal-before-send are kept.

**REJECTED: cap the offset at 94 and keep signing at the request.** Every
post would land, but the reference age stays `offset + 6`. The request
height is still public, and for an instant staker so is the funding
block (§1.2). Reopen if the reference age stops being visible on chain:
it is not, because the daemon checks it (`tx_against.rs:320-324`).

**What the alternative (sign at the request) keeps.** The defect.

**Falsifier.** Signing at due is unsafe if signing needs something
unavailable at the due tick. Candidates: a secret not in the held bundle,
a curve-tree path the wallet cannot build at that reference, or a posture
the plan cannot carry. The precedents above say none applies. A test that
assembles from a reloaded plan after a restart settles it.

### BD-Q4 — How wide is the window?

**Default: one settlement epoch, `W = SETTLEMENT_EPOCH_BLOCKS` (10,000
blocks, about 13.9 days), typed from the consensus constant rather than a
literal. The cost is stated, and the homeostasis check runs before the
ruling.**

**Reason: the targeted direction's cover is the bond-post rate.** The
observer from BD-Q1 can work in two directions.

- **Untargeted (backward).** It sees a bond post and searches the
  principals it watches for a send in `[post − W, post]`. Its cover is
  every send by a watched principal, because a funding transfer looks
  like any transfer. This is what the sim measured: "candidate-set mean
  `1 → 7 → 13 → 25` across windows `0 → 300 → 600 → 1200` blocks" at a
  background rate of 0.02 per block (`STAKER_ARCHIVAL_SIM.md:3500-3512`).
  `600` was sized here.
- **Targeted (forward).** It knows a principal and saw it send at `T`
  (the intent's adversary, and WI-4's). It searches the bond posts in
  `[a, a + W]`, with `a = h_f + 16`. Its cover is other bond posts, which are far
  scarcer.

**The rate.** No bond-post rate figure exists. The exit round's model is
the nearest: `ρ ≈ N_P × c / SEB`, with `N_P ∈ 79–154` bonded personas and
per-epoch churn `c ∈ [0.02, 0.2]`
(`docs/completed/ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md:265-284`). In a
stationary population, joins replace exits, so the join rate takes the
same box. That equality is this round's reasoning, not a measurement. The
forward candidate count is `ρ × W`, and the window for `N_t` candidates
is `W ≥ (N_t − 1) / ρ` (FD4's shape):

| Window | Latency (mean / max) | Other bond posts in window (`79, 0.02` … `154, 0.2`) | Window for `N_t = 10` (`TARGET_ANON_SET`, WI-4 `:238`) |
| --- | --- | --- | --- |
| `600` (the sentinel) | 10 h / 20 h | 0.09 … 1.85 | — |
| `1,000` (the sim's free ceiling, below) | 17 h / 33 h | 0.16 … 3.1 | — |
| `10,000` (1 SEB) | 6.9 d / 13.9 d | 1.6 … 31 | — |
| derived | — | — | 56,962 … 2,922 blocks (5.7 … 0.3 SEB) |

At the `600` sentinel, a targeted observer finds fewer than two other bond
posts at every corner of the box. Against that observer, `600` covers
almost nothing. One SEB is the smallest candidate that leaves cover at the
lean corner and reaches `N_t` at the thick corner. It is also the figure
gate-6 R4 already ratified for this spacing
(`ARCHIVAL_TIMING_CONSTANTS.md:321`), as a window this time rather than a
floor (BD-Q5).

**The cost, stated (rule 82).**

- **Latency.** A stake starts earning up to 13.9 days after the request
  (mean 6.9 days) instead of up to 20 hours.
- **The economy.** The sim treats the standoff as free only up to 0.10
  epoch (about 1,000 blocks; `STAKER_ARCHIVAL_SIM.md:3494-3501`). One SEB
  is on the economic axis, so the staking sim's homeostasis check runs
  before the ruling, in verification mode against the production lever,
  not as an analytical bound.
- **What the user sees.** `staking_info` shows a planned stake with the
  date it will be posted by. The field is WR-Q1's (`in_flight`), and
  whether the response carries the due is WR-Q5's (§6).

**Set once, not shrunk later.** The window is wallet-side and
golden-vector-pinned (`shekyl-standoff/src/draw.rs:59-70`, `:78`). A later change
splits the network into two delay distributions for as long as old
wallets post, which is itself a fingerprint. The principal-side Tor flip
covers the wallet→daemon link. It does not remove the first stem edge of
an own node's P2P broadcast, so the network-origin observer survives it.
The default is sized for the world with that observer, and kept.

**Launch.** At genesis the first bond posts have no cover at any width.
WI-4 §16.5 proposes a launch-window rate cap on bond posts with no number
(`ARCHIVAL_BOND_WI4_MEASUREMENT.md:2463-2464`). That is a separate
question, recorded here and not decided.

**What the alternatives change.**

- **`600`:** free on the economic axis, and it defends only the untargeted
  direction.
- **The derived window:** reaches `N_t` everywhere, but at the lean corner
  it costs 5.7 epochs (about 79 days) of latency.
- **`1,000`:** the economic ceiling, with at most three forward candidates.

**Falsifier.**

- If the testnet join rate is at least 0.015 per block (about 150 joins
  per epoch), `600` reaches `N_t = 10` forward, and the cost side picks
  it.
- If the join rate is below `9 / 10,000` per block, 1 SEB misses `N_t`.
  The ruling then either widens the window or records the shortfall as a
  conscious concession.
- If the homeostasis check shows a one-epoch entry delay moves the
  equilibrium, the window comes down and the concession is stated.

### BD-Q5 — What happens to `MIN_COLD_START_SPACING`?

**Default: deleted, along with `EconomicSpacing` and `SebSpan`, whose only
consumer it is** (`engine/stake_timing.rs:129-135`, `:160-174`,
`:192-203`; the type list in `engine/mod.rs:389-390`). The one-epoch
figure survives as BD-Q4's window if that is ruled.

**Reason.** A floor ("at least one epoch after funding") is a different
object from a window ("uniform over one epoch from funding").

- Against an anchor the observer holds, a floor is a constant shift that
  the observer subtracts. It costs a full epoch and buys no cover.
- It also hands the observer a structural fact, "never within an epoch of
  the funding". The gate refused that shape when it kept zero in the draw:
  excluding a value "hand[s] the observer a structural fact … that they
  did not have" (`ARCHIVAL_FIREWALL_GATE6.md:2201-2210`).
- Under BD-Q2 the window measures from the funding, which is the job the
  floor was named for. So the floor is subsumed, and dead code does not
  survive the round (rule 15).

**The documents that go with it, when ruled:**

- the §7 row (`ARCHIVAL_TIMING_CONSTANTS.md:321`), restated as the window;
- `ARCHIVAL_BOND_CONSTRUCTION.md:665-669`, which still describes the
  three-event model;
- the SP-2.d passages of `ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md`
  (`:182-187`, `:324-326`, `:397-399`);
- the citation at `engine/stake_timing.rs:160-163`, which points at
  CONSTRUCTION §10 for SP-2.d, a section that does not hold it.

**What the alternative changes.** Wiring the floor as well
(`due = a + SEB + s`) adds one epoch of pure latency for no cover.
Wiring it alone (no draw) leaves a constant offset from the funding, which
gives no cover at all.

**Falsifier.** An observer model under which a floor enlarges the
candidate set beyond what the same-width window gives. The candidates are
the bond posts in the window wherever the window sits, so none is known.

---

## 4. Attacker objectives (rule 26 A3)

| Objective | Route |
| --- | --- |
| **O1.** Link principal to `P` from the funding broadcast (network origin, forward). | BD-Q4: the window is sized against it. The residue at thin rates is stated there. |
| **O2.** Read the request height, or the funding block, off the bond's reference. | BD-Q3: absorbed. The reference age at broadcast is 6. |
| **O3.** Have the wallet resend a dead post until the alarm, keeping the funding reserved for about 30 hours and the stake unlanded. | BD-Q3: absorbed (signed at due, re-signed at `REBUILD_AT`). WR-Q3's expiry covers any residue. |
| **O4.** Tie the post's send to the wallet opening, when the due fell while the wallet was closed. | Discipline note. Today's sealed post sends at reopen too. Whether the post rides the serving-launch standoff (`engine/stake_timing.rs:206`, SH-2b-2) is the bond lane's forward action, posed at implementation. |
| **O5.** Fingerprint wallets by window cohort after a window change. | BD-Q4: the window is set once. |
| **O6.** A remote daemon (no own node) receives both the funding transfer and the bond post from one client. | No window helps: it sees the post submitted. Conceded under the own-node posture (`engine/transaction_submitter.rs:479-483`). The routes are the principal-side Tor flip (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:1988`) and the per-`P` submit posture (2d-2). Recorded, not absorbed. |

---

## 5. Proving it

Tests that land with the implementation of the rulings:

- **Replace** #1079's ignored test. A post due at `a + s` is signed at its
  first send and carries reference age 6. With `StaleRoot` it is re-signed
  at `REBUILD_AT`, not resent to the alarm.
- **Instant staker:** a request at `a` produces a post whose reference
  height is not `h_f + 10`.
- **Restart between request and due:** the plan reloads, `s` is unchanged,
  and the post assembles from the re-derived bundle.
- **Elapsed age:** a request past `a + s` posts at the next tick, with no
  added draw.
- **Multi-input:** the anchor is the greatest `spendable_height` among the
  reserved outputs.
- **Schema:** the version bump and snapshot, and a v12 seal failing closed.
- **No dead code:** `rg -n 'MIN_COLD_START_SPACING|EconomicSpacing|SebSpan' rust`
  returns nothing (BD-Q5 as defaulted).

---

## 6. What passes to the wallet-RPC round (#1079)

Each carry is recorded in both documents (rule 26 A5).

- **§1.1 there points here.** The FOLLOWUPS row "The bond-post delay does
  not decorrelate the funding transfer from the bond" is owned by this
  round.
- **WR-Q1 (`in_flight`)** gains a state for a planned, unsigned stake with
  its post-by date, if BD-Q3 is ruled.
- **WR-Q3 (expiry)** keys on a record's reference height. A planned stake
  has none until it is signed, so its ending needs its own rule. An
  unsigned plan can also be withdrawn by dropping the record: no byte of
  it was ever sent, so it cannot land later. That differs from the
  cancel-by-spending WR-Q3 rejects. Which one applies is WR-Q3's to rule.
- **WR-Q5 (what the response reveals)** decides whether `staking_info`
  carries the due height.

---

## 7. What this round does not do

- No code and no test changes before the rulings.
- It does not choose the launch-window rate cap (BD-Q4, "Launch").
- It does not build the principal-side Tor default flip
  (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:1988`), and its window does not
  depend on it.
- It does not edit method note 8, the WI-4 banner or the timing table
  before the rulings (BD-Q1, BD-Q5).
