# Bond-post delay — what it decorrelates: Round 0

**Status:** RULED IN PART — Round 0 posed 2026-10-15; **BD-Q1, BD-Q2, BD-Q3
and BD-Q5 ruled 2026-10-16** (Rick). **BD-Q4, the window, is open**, with
the inputs it needs first (§3). No code in this PR; the implementation
slice (BD-Q2, BD-Q3, the BD-Q5 deletion) is next and does not wait for
BD-Q4 ([`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)).

**Ground:** `shekyl-core` `dev` at `0419e6780` (the #1082 merge, after
the wallet-RPC round, #1079, merged ruled). Every `file:line` below was
read at that commit. Paths under `engine/` are in
`rust/shekyl-engine-core/src/engine/`.

**Identifier family:** `BD-Q1…BD-Q5` (the questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth.

**Sequencing:** the round rules **before `DEL-008`**
([`DAEMON_REDB_STORE.md`](DAEMON_REDB_STORE.md) §12). That deletion is when
the Rust daemon starts accepting bond posts and the defect goes live.
Until then the C++ daemon refuses every kind-5 JoinMarket post before any
reference check, which hides it. **The deadline binds BD-Q3, not BD-Q4.**
The window is single-sourced (`shekyl-standoff/src/draw.rs:80`, typed in
`engine/stake_timing.rs:189-190`): the implementation builds against it,
and BD-Q4's ruling changes one constant and its golden vector. The wallet-RPC round
([`WALLET_RPC_STAKING_OUTCOMES.md`](WALLET_RPC_STAKING_OUTCOMES.md),
`WR-Q1…WR-Q5`) is ruled and not yet built; §6 lists what passes between
the two rounds.

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
| The stake request sweeps only funding records the sealed P-scan has found (`engine/bond_orchestrator.rs:742-777`), and that scan covers only blocks below `claimed count − ARCHIVAL_REORG_DEPTH_BLOCKS` (720): a funding output at height `h_f` is first sweepable at tip `h_f + 720`. | `engine/pscan/task.rs:245-252`; `engine/pscan/start.rs:91-99` |
| The delay is drawn at the request: `bond_post_offset_blocks ~ U[0, 600]`, one unbiased draw. | `engine/stake_engine/actor.rs:154-170`; `shekyl-standoff/src/draw.rs:96-98` |
| `anchor_t0` is the daemon-claimed tip at the request. The reference is `min(synced tip, ingested tip) − REF_ANCHOR_AGE` (6). | `engine/bond_orchestrator.rs:443-461`, `:555-557` |
| The signed bytes are sealed with `anchor_t0` and the offset; `due = anchor_t0 + offset`. | `engine/bond_orchestrator.rs:662-670`; `engine/pscan/dispatch.rs:265-272` |
| Every send, first or retry, re-sends the sealed bytes. | `engine/pscan/dispatch.rs:763-769`; `ARCHIVAL_BOND_WI3_DISPATCH.md:328-329` (§3.6: "never re-drawn for existing bytes") |
| A reference older than `MAX_AGE` (100) is refused. A proof built at the canonical anchor is submittable for `PROOF_VALIDITY_HORIZON` (94) blocks. | `shekyl-curve-tree/src/reference.rs:95-106`; `shekyl-chain-rules/src/rules/tx_against.rs:319-341` |
| `REF_ANCHOR_AGE` is privacy-canonical, so "the on-wire reference age does not fingerprint the wallet". | `shekyl-curve-tree/src/reference.rs:75-84` |
| The Rust daemon answers a too-old reference `StaleRoot`; the wallet classes it retryable and resends the same bytes until the 900-block alarm. | `shekyl-daemon-rpc/src/submit/engine.rs:374`; `engine/transaction_submitter.rs:270`; `engine/pscan/dispatch.rs:213-216`, `:825-831` |
| `600` is a self-declared provisional sentinel; its multi-event derivation is void. | `shekyl-standoff/src/draw.rs:71-80`; `ARCHIVAL_BOND_WI4_MEASUREMENT.md` §13.1, `:796-806` |
| `MIN_COLD_START_SPACING` (one settlement epoch between funding and bond) is `#[allow(dead_code)]`, "inert until cold-start spacing check is wired". | `engine/stake_timing.rs:192-203` |

### 1.2 What follows

- **Most posts never land.** An offset over 94 sends a reference already
  past the window: 506 of the 601 equally likely offsets, about 84 %.
  Each is resent unchanged until the alarm. The ignored test
  `a_bond_post_sent_past_its_proof_lifetime_is_resent_unchanged_to_the_horizon`
  (`engine/pscan/dispatch_tests.rs:1293`) shows it. WR-Q3 (ruled, not
  built) stops any send past a record's end date and releases the funds
  there. That bounds the waste; the post still never lands.
- **The post shows when it was signed.** A post sent `offset` blocks after
  signing carries reference age `offset + 6`. Any node can subtract and
  recover the request height. The delay hides nothing about the event it
  is measured from.
- **For a staker who stakes as soon as funding allows, the reference
  points at the funding block.** The earliest request is at tip
  `h_f + 720`, where `h_f` is the funding output's block: the sealed P-scan
  must have covered it (§1.1). That post's reference height is `h_f + 714`,
  so `reference − 714 = h_f`, to within one scan tick (60 s, under one
  block), whatever the offset. A chain-only observer reads the funding
  block off the bond post. No product path spaces the two calls: `stake_in` and
  `first_stake` are separate (`shekyl-wallet-rpc/src/staking_actions.rs:79-96`;
  the GUI calls `first_stake` alone, `shekyl-gui-wallet`
  `src-tauri/src/engine_session.rs:395`). A user who stakes as soon as
  `first_stake` accepts is on this path.
- **The delay is measured from the wrong event.** The intent is to
  separate the bond from the funding. The draw starts at the request,
  which is a private moment, and the guard that measures from funding is
  unwired.

The defect and the cover question are separable. **Signing at the due
time (BD-Q3) removes the dead posts and the reference leak whatever the
window is.** BD-Q4 decides how much cover the delay buys.

---

## 2. What the posture says

- **Method note 8** counts events on the chain, not in the pipeline. An
  event counts only if an observer can see it as distinct, and the funding
  transfer is "not attributable, therefore not an anchor"
  (`ARCHIVAL_FIREWALL_GATE6.md:2212-2220`; pass-4 (d) closure `:1589-1617`).
  Its "invisible to every observer the posture admits" is scoped to the
  chain observer (`:2222-2227`, BD-Q1).
- **The WI-4 retraction** keeps the spread for one adversary only: "live
  defense-in-depth only against an off-chain-anchored adversary — someone
  who knows the principal and saw them act at time `T` — and dead against
  the chain observer". It freezes the rule for `600`: it re-derives only on
  "(a) a measurable off-chain anchor-precision model arriving, or (b) a
  pure cost-side (latency) decision". The banner names the network-origin
  observer as the measurable case, with a one-block anchor
  (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:776-811`).
- **The gate's threat table admits network observers**: "Local / ISP"
  (principal clearnet link timing) and "Partial passive (GPA-lite)"
  (`ARCHIVAL_FIREWALL_GATE6.md:1036-1050`).
- **A wallet without its own node reaches its daemon over clearnet by
  default.** "Until it lands, a passive network observer needs *no user
  error* to correlate principal daemon traffic with on-chain events — the
  vantage is granted by our default" (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:4072-4086`);
  the principal-side default flip is "NOT YET BUILT" (`:1988`).
- **Dandelion++ does not cover the first edge.** A wallet submission stems
  from the daemon that accepts it (`DAEMON_RELAY_PRIVACY.md:796-805`), and
  stem-and-fluff "does not hide the origin from a passive observer that
  already sees the first stem edge" (`:1238`). What the default Tor
  posture does about that edge is BD-Q4's first input.

---

## 3. Rulings and the open question

### BD-Q1 — The observers of the funding event — RULED 2026-10-16

**Ruled.** The posture admits three observers, each with a named anchor
and channel. For the network-origin observer and the funding counterparty
the funding transfer is an event.

| Observer | What it sees (`T` and its channel) | Anchor precision |
| --- | --- | --- |
| **Chain-only** | The bond post, which names `P`. The funding transfer is an unattributable FCMP++ transfer. | None once BD-Q3 is built. Until then the reference age gives it the request height and, for an instant staker, the funding block (§1.2). |
| **Network origin** of the principal's transfer: the ISP or first stem edge of the principal's node, a GPA-lite relay fraction, or the remote daemon and its link when the wallet does not use its own node | The funding transaction leaving the principal. It learns the transaction and so its block. | One block for an IP link to the transaction. What the default Tor posture leaves of this vantage is BD-Q4 input 1. |
| **Funding counterparty**: whoever delivered the coins the principal funds `P` with (the "on-ramp witness", `ARCHIVAL_BOND_WI4_MEASUREMENT.md:4097-4099`) | Its own delivery to the principal. "The chain goes dark to the counterparty too": it does not see the principal's later transfer to `P`. | Coarse, set by the principal's own behaviour between receiving and funding. It reaches block precision only if it also holds the network-origin position. |

Method note 8's "invisible to every observer the posture admits" holds for
the chain observer; the scoping sentence is in
`ARCHIVAL_FIREWALL_GATE6.md:2222-2227`. The WI-4 banner names the
network-origin observer as the measurable case
(`ARCHIVAL_BOND_WI4_MEASUREMENT.md:800-808`).

**Why.** Note 8's own test decides it: "an event counts only if an
observer can see it as distinct", and "asking *which observer* names the
excluded posture". The network-origin observer sees the funding transfer
as distinct, because it watched it leave the principal. The gate already
admits that observer (§10.1's Local/ISP and GPA-lite rows), and our
defaults grant it (WI-4 trace 1). The design intent names it: someone who
sees the funding appear and wants to find the bond. The order coin stays
retired: the chain still carries one attributable event, and the delay is
a jitter against the funding anchor, not a permutation.

**Reopens if** the principal's funding transfer reaches the network with
its origin hidden from every network vantage by default. BD-Q4 input 1
records what the default does today.

### BD-Q2 — What the delay is measured from — RULED 2026-10-16

**Ruled.** The delay is measured from the first height at which the
funding can be spent into a bond. Elapsed time counts, and no fresh draw
is added.

- **The anchor** `a` is the first tip height at which the funding can be
  swept into a bond, taken over the reserved funding outputs (the latest
  governs):
  `a = max(spendable_height + REF_ANCHOR_AGE, height + ARCHIVAL_REORG_DEPTH_BLOCKS)`.
  The first term puts the output's leaf in the tree at the canonical
  reference; the second is the sealed P-scan covering its block (§1.1).
  For an ordinary output that is `h_f + 720`. Both terms come from the
  wallet's own record (`pscan_state.rs:237`, `:259`) and are the same for
  every wallet, so the observer gains nothing from them.
- **The draw** `s ~ U[0, W]`, taken once at the request and persisted.
  The wallet persists `s`, not the due. A re-draw is refused: a second
  sample biases the post earlier.
- **The due, on the dispatch clock.** The dispatch clock is a claimed
  *count*, whose tip is `count − 1` (`engine/pscan/block_source.rs:94-109`),
  so the anchor's count is `a + 1`: `due = max(a + 1 + s, the request's
  count)`. If it has already passed at the request, the post goes at the
  next tick.
- **The clock.** `a` is recomputed from the live funding record at each
  tick and compared on the daemon-claimed count clock.
  A reorg that moves the funding output moves the anchor with it.
  `block_source.rs:179-182` keeps the synced and ingested *tip* clocks out
  of the due; a record's `spendable_height` is a block's height, not a tip
  clock.

**Why.**

- **The anchor is the event the observer holds.** The network-origin
  observer anchors at the funding block, and the request is private (with
  BD-Q3 nothing is emitted at the request). A delay measured from the
  request adds the principal's reaction time, which is not
  wallet-controlled; for a staker who stakes as soon as allowed it is a
  constant.
- **`+720` is a constant, so it buys nothing.** Every wallet shares
  `ARCHIVAL_REORG_DEPTH_BLOCKS` and `SPENDABLE_AGE + REF_ANCHOR_AGE`, so the
  observer subtracts the anchor's offset. Measuring from `a` rather than
  `h_f` keeps the whole window drawn. From `h_f`, every draw below 720
  would collapse onto the first sweepable tip, a point mass at a public
  offset from the observer's anchor; with `W ≤ 720` that is every draw.
- **Elapsed time counts.** A request at elapsed age `e` past `a` lands at
  `a + max(e, s)`. What the observer sees of `post − a` is uniform over
  `(e, W]` with a point mass at `e`, and `e` is the principal's private
  choice, so the point mass falls where the observer cannot name it.
- **The latest anchor governs a multi-input bond** (the
  logged exception, `engine/bond_orchestrator.rs:581-586`). The window
  covers the last funding transfer the observer may hold; earlier ones are
  separated by more.

**Wargame: a stake made the instant funding is sweepable.** The request
comes at `a = h_f + 720` (`e = 0`).

- **Today:** the post is signed at `a` with reference `h_f + 714` and sent
  at `a + s`. Its reference age `s + 6` gives away `a`, and so `h_f`. The
  network observer's link is exact whatever `s` is, and the chain observer
  learns the funding block.
- **Under the ruling:** the post lands at tip `a + s`, signed then, with
  reference age 6. The observer's candidates are the JoinMarket posts in
  `[a, a + W]`.
- A request anchor with signing at due would give the same result here,
  because the request is at `a`. The two anchors differ only for late
  requests, where the request anchor adds latency and no cover.

**Reopens if** an observer can see the request instant: a remote daemon
receiving the request's round trips (`get_fee_estimates`, the claimed tip;
`bond_orchestrator.rs:555-557`, `:958-962`), or a GUI or wallet-RPC host
across a network. That observer holds the request as an anchor, and a
late post lands at the request instant. Under the own-node posture these
hops are loopback and the observer does not exist.

### BD-Q3 — Signing at the due time — RULED 2026-10-16

**Ruled.** The request seals an unsigned plan. At the due tick the actor
assembles, proves and signs the post with a fresh reference at the
canonical age, and the signed bytes are sealed before the first send. The
schema bump is shared with, or follows, WR-Q2/WR-Q3's v13.

Signing at the due time makes the reference age at broadcast the
standard 6. That removes the reference leak (§1.2) and the dead posts
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
| The reservation, `funding_gindexes` | Keeps the cadence driver's claims and drains off the funding until the bond spends it. `reserved_gindexes()` already unions it (`shekyl-engine-state/src/pending_post_block/mod.rs:602-628`). | Held. |
| The draw `s` (BD-Q2) | The due is `max(a + 1 + s, request)` on the count clock. A re-draw is refused. | `bond_post_offset_blocks` |
| The holdings descriptor (the posture) | Assembly moves to the due tick, and the posture is the caller's. Today "nothing posture-shaped is persisted" (`engine/bond_orchestrator.rs:827`) because the posture is consumed at once. | Not held. New. |
| Not the fee | Estimated at the due tick from the daemon's live estimate, as `first_stake` does now (`engine/bond_orchestrator.rs:958-962`). | — |
| Not the tx bytes, the reference or the key image | Produced at the due tick. | `tx_bytes` |

That is a persisted-schema change: a planned state (or kind) in the
pending-post block, the posture added, `anchor_t0` replaced by the anchor
rule, and the record's `reference_height` durable (one per record).
`PENDING_POST_VERSION` (12, `pending_post_block.rs:94`) bumps under rule
42 with its snapshot (`shekyl-engine-state/schemas/pending_post_block.snap`).
WR-Q2 and WR-Q3 take v13 for a durable `reference_height` (ruled, not
built); that is this record's field, and this change shares that bump or
takes the next. A mismatched seal
fails closed, as today (`:91-93`).

**The states.** W1 (preflight, nothing durable) and W2 (`bonded_slots`
written, no record) stay. The **planned** state (durable plan and
reservation, no signature) comes before **signed** (bytes sealed,
`Pending`), then `Dispatched`.

**Surviving a restart.** The plan reloads with the pending block. The
bonded slot is re-derived at open. At the first tick at or past due, the
driver has the engine assemble, then seals the signed bytes, then sends.
A wallet closed at due posts on the first tick after reopening, signed
then.

**Rule 1 — one submitted version per record.**

- **Never sent.** No submit was attempted. The post may be re-anchored
  and re-signed freely, and it is re-signed before its first send whenever
  its reference is not the canonical one for the current tip
  (`select_reference_height`, `shekyl-curve-tree/src/reference.rs:135`),
  so the first send carries reference age 6 and the full 94-block
  lifetime. This covers a post signed and sealed at due whose send did not
  happen before the wallet closed. The ordinary pre-broadcast threshold,
  `should_reanchor` at `REBUILD_AT` (`reference.rs:116`, `:249-257`; CT-5d,
  `engine/traits/pending_tx.rs:218-232`), is too loose here: a post sealed
  at age 6 and sent after a restart ten blocks later would go out at
  age 16.
- **Sent** means a submit was *attempted*. The state is recorded durably
  before the submit call, so a crash during the call counts as sent. That
  is conservative: it can only hold funds longer, never create a second
  version.
- **A sent record is never re-signed.** It resends the same bytes until
  its end date and ends there through WR-Q3 (`reference_height +
  MAX_AGE`, released when the scan's sealed frontier reaches it).
- **Why.** Re-signing after a send moves the end date, so a post that
  never lands (a censoring daemon) would re-sign forever and the record
  would never end. Re-signing is also the only source of two live versions
  spending the same key images. A sent post that expires on a healthy
  network is a real failure the user should see (rule 82): its outcome is
  `expired`.
- **Re-staking after `expired`.** The new post goes on its first tick,
  with no fresh draw. The first broadcast already showed network observers
  when the post went out, so a second delay hides nothing and only adds
  latency.

**Rule 2 — no daemon verdict releases a submitted record.**

- On a terminal verdict the wallet stops sending and raises the alarm; no
  automatic re-assembly (`ARCHIVAL_BOND_WI3_DISPATCH.md` §3.6). It keeps
  the record and the reservation.
- **The verdict never decides the outcome; the chain does.** At the end
  date, if the scan saw the post land, the confirmed path wins, whatever
  the daemon said. If it did not land, the outcome is `rejected` with the
  daemon's reason as a user sentence (rule 81), and `funds_return_at` is
  the end date.
- **Why.** From the first submit the daemon holds valid bytes. A lying
  daemon can report a terminal verdict, wait for the wallet to release the
  reservation and drop the slot, then relay the bond inside the window. A
  bond then lands for a dropped slot, and "a dropped slot stays burned"
  (`engine/stake_persist.rs:212-214`): the harm WR-Q3's own rejected
  alternatives name. A conflict on the very first send is no exception:
  with one version and the reservation held, its only honest cause is
  another wallet holding the same seed, and the chain resolves that too.
- **Cost.** A refused stake holds its funds until its end date is final,
  about 94 + 720 blocks after it was signed. The user sees the reason at
  once: its `in_flight` state is `refused`, with `reason` and
  `funds_return_at`, until the end date, and `expired` with the same
  `reason` after it. `rejected` is only the end-date outcome.

Today's dispatch driver does the opposite on both counts: it resends the
same bytes past the end date, and its terminal arm removes the record and
releases the reservation (`engine/pscan/dispatch.rs:794-803`). The
implementation slice changes both.

**What changes for WI-3.** The dispatch driver "never constructs or
signs" (`ARCHIVAL_BOND_WI3_DISPATCH.md:34-35`). Under this ruling it
triggers assembly through the engine at due, and its verdict handling
follows Rules 1 and 2. The single-writer seal discipline (§3.3) and
seal-before-send are kept.

**Reopens if** signing at due needs something unavailable at the due
tick: a secret not in the held bundle, a curve-tree path the wallet cannot
build at that reference, or a posture the plan cannot carry. The
precedents above say none applies; a test that assembles from a reloaded
plan after a restart settles it.

### BD-Q4 — How wide is the window? — OPEN

**Open.** The `600` sentinel holds until this is ruled. The window is
fixed at genesis: it is wallet-side and golden-vector-pinned
(`shekyl-standoff/src/draw.rs:59-70`, `:78`), and once wallets are live a
change splits them into two delay distributions, which is itself a
fingerprint. Before genesis it can be chosen with the network posture
known, at no fingerprint cost.

**Implementation does not wait for it.** `W` is single-sourced
(`shekyl-standoff/src/draw.rs:80`, typed in `engine/stake_timing.rs:189-190`).
BD-Q2, BD-Q3 and BD-Q5 build against it, and the ruling changes one
constant and its golden vector.

**Answered at source.**

1. **What the default network posture leaves of the network-origin
   observer.**
   - **Own-origin broadcast over Tor is designed and default-on.** The
     default P2P posture runs clearnet and Tor together
     (`INPUT_GRAMMAR.md:361`, IG-Q3). A node's own transactions ride a
     stem slot drawn from its hidden-address (Tor) outbound sessions when
     it has any (`TOR_COVER_POSTURE.md:53-66`; shipped in PR-1, #1018). The
     first stem peer receives the transaction over Tor, so the
     IP-to-transaction link at the first stem edge is gone by default.
   - **The wire vantage stays under the default managed Tor.** That Tor is
     a client-only second process: "Originated cells then travel that
     client's own OR connections" (`TOR_COVER_POSTURE.md:295-296`), and "a
     wire observer can still separate that burst from relay volume"
     (`:29-31`). Only the operator-relay posture (§1) hides originated
     cells, and that posture is the operator's choice, not the default. So
     by default the ISP sees *when* the node originated something, not
     *which* transaction. Its anchor is a timing match between that burst
     and the transaction's appearance, and its precision is unmeasured:
     Tor's cover class is `Volume`, "unmeasured, pending TRC-1" (`:50`).
   - **`DAEMON_RELAY_PRIVACY.md` §42.1's carrier** (stem + own ≈ 0.5 %
     utilisation) does not apply on the Tor zone: TRC's relay posture
     replaced it there (the section heading, `DAEMON_RELAY_PRIVACY.md:8729`).
   - **A wallet without its own node** still reaches its daemon over
     clearnet by default (§2), and that daemon sees the submission.

   So, under the default posture, the network-origin observer is the
   ISP's burst-timing vantage plus the remote-daemon case, not an IP link
   at the first stem edge; under the operator-relay posture it is
   residue. The window's cost, every staker waiting, is weighed against
   the burst-timing anchor's precision. Input: **TRC-1**.
2. **The cover count.** The targeted observer's
   cover is **every JoinMarket post**, and only those.
   - The `post_kind` byte is cleartext; a JoinMarket is `0x05` and nothing
     else is (`shekyl-wire/src/transaction.rs:96`, `:664-695`).
   - `HoldingsUpdate` (`post_kind 3`) is REJECTED; there are no holdings
     re-posts (`ARCHIVAL_BOND_GATE4.md:828`).
   - A Release is `Other(2)`, distinguishable by its kind. A Reinstate
     posts for an existing record with zero credit, distinguishable by its
     known `P` id (`ARCHIVAL_BOND_GATE4.md:356-366`).
   - A holdings change is a rotation: a new persona's JoinMarket plus the
     old persona's Release (`ARCHIVAL_BOND_GATE4.md:702-712`). A rotation's
     JoinMarket names a fresh persona, as a first join does, so it is
     cover.

   FD4's churn `c` counts unbonds and holdings drops
   (`docs/completed/ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md:273`). Under the
   immutable bond each drop is a rotation, which emits a JoinMarket. So
   the join rate is FD4's box as an estimate, not a bound, and any
   wallet-driven persona rotation outside `c` adds to it.

**Still owed:**

- **TRC-1's burst-timing result**: the precision of the ISP's
  burst-timing anchor (input 1).
- **A measured join rate**: no bond-post rate figure exists; the box below
  is FD4's model.
- **The homeostasis run.** Anything above about 1,000 blocks is on the
  economic axis (the sim treats the standoff as free only up to 0.10
  epoch, `STAKER_ARCHIVAL_SIM.md:3494-3501`). The staking sim runs the
  candidate in verification mode against the production lever before the
  ruling.

**The candidates as they stand.** The observer from BD-Q1 can work in two
directions.

- **Untargeted (backward).** It sees a bond post and searches the
  principals it watches for a send in `[post − W, post]`. Its cover is
  every send by a watched principal, because a funding transfer looks
  like any transfer. The sim measured this: "candidate-set mean
  `1 → 7 → 13 → 25` across windows `0 → 300 → 600 → 1200` blocks" at a
  background rate of 0.02 per block (`STAKER_ARCHIVAL_SIM.md:3500-3512`).
  `600` was sized here.
- **Targeted (forward).** It knows a principal and saw it send at `T`
  (the intent's adversary, and WI-4's). It searches the JoinMarket posts
  in `[a, a + W]`, with `a = h_f + 720`. Its cover is other JoinMarkets,
  which are far scarcer.

With `ρ ≈ N_P × c / SEB`, `N_P ∈ 79–154` and `c ∈ [0.02, 0.2]`
(`docs/completed/ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md:265-284`), the
forward candidate count is `ρ × W`, and the window for `N_t` candidates
is `W ≥ (N_t − 1) / ρ` (FD4's shape):

| Window | Latency (mean / max) | Other JoinMarkets in window (`79, 0.02` … `154, 0.2`) | Window for `N_t = 10` (`TARGET_ANON_SET`, WI-4 `:238`) |
| --- | --- | --- | --- |
| `600` (the sentinel) | 10 h / 20 h | 0.09 … 1.85 | — |
| `1,000` (the sim's free ceiling) | 17 h / 33 h | 0.16 … 3.1 | — |
| `10,000` (1 SEB) | 6.9 d / 13.9 d | 1.6 … 31 | — |
| derived | — | — | 56,962 … 2,922 blocks (5.7 … 0.3 SEB) |

- **`600`:** free on the economic axis; fewer than two forward candidates
  at every corner, so it defends the untargeted direction only.
- **One SEB (the round's proposal):** the smallest candidate with forward
  cover at the lean corner and `N_t` at the thick one. Costs: a stake
  starts earning up to 13.9 days after the request (mean 6.9), and it is
  on the economic axis (input 3).
- **The derived window:** reaches `N_t` everywhere, at up to 5.7 epochs
  (about 79 days) of latency at the lean corner.

**What the user sees.** Under WR-Q1 and WR-Q5 as ruled, a planned stake is
an `in_flight` entry in state `pending`, and "a `pending` entry reveals
nothing about when it will be sent". At `600` that is up to 20 hours; at
one epoch it is up to 13.9 days with no date, which reads as stuck
(rule 82). The WR-Q5 relay (§6) depends on the width ruled here.

**Launch.** At genesis the first bond posts have no cover at any width.
WI-4 §16.5 proposes a launch-window rate cap on bond posts with no number
(`ARCHIVAL_BOND_WI4_MEASUREMENT.md:2463-2464`). It is a separate question,
recorded here and not decided.

**What decides it.** If the join rate reaches 0.015 per block (about 150
joins per epoch), `600` reaches `N_t = 10` forward and the cost side picks
it. A coarser anchor does not remove the forward observer: with TRC-1's
measured anchor uncertainty `u` (in blocks), its candidates are the
JoinMarkets in `[a − u, a + W]`, so the window is sized with `W + u`, and
the remote-daemon case is weighed alongside it, not instead of it. If the
homeostasis run shows a one-epoch entry delay moves the equilibrium, the
window comes down and the concession is stated.

### BD-Q5 — `MIN_COLD_START_SPACING` — RULED 2026-10-16

**Ruled.** `MIN_COLD_START_SPACING`, `EconomicSpacing` and `SebSpan` are
deleted (`engine/stake_timing.rs:129-135`, `:160-174`, `:192-203`; the type
list in `engine/mod.rs:389-390`), with Rick's authorization to remove the
landed code. The deletion lands in the implementation slice with BD-Q2 and
BD-Q3, which touches `stake_timing.rs` anyway; the drifted SP-2.d citation
at `engine/stake_timing.rs:160-163` goes with it. This PR carries the doc
edits:

- the §7 row (`ARCHIVAL_TIMING_CONSTANTS.md:321`) restated as the bond-post
  delay measured from the funding, width per BD-Q4;
- `ARCHIVAL_BOND_CONSTRUCTION.md:665-671`, the three-event model dropped;
- `ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md` SP-2.d (`:180-188`, `:320-323`,
  `:389-393`) and R0-D3 (`:737-746`): the floor is replaced by BD-Q2's
  anchor. Amount decoupling, the generic transfer to `P`, is unaffected.

**Why.** A floor ("at least one epoch after funding") is a different
object from a window ("uniform from funding").

- Against an anchor the observer holds, a floor is a constant shift that
  the observer subtracts. It costs latency and buys no cover.
- It also hands the observer a structural fact, "never within an epoch of
  the funding". The gate refused that shape when it kept zero in the draw:
  excluding a value "hand[s] the observer a structural fact … that they
  did not have" (`ARCHIVAL_FIREWALL_GATE6.md:2201-2210`).
- Under BD-Q2 the delay is measured from the funding, which is the job the
  floor was named for. Dead code does not survive the round (rule 15).

### Rejected alternatives

- **BD-Q1, chain-only posture (note 8 unscoped):** the delay would protect
  nobody, and it contradicts GATE6 §10.1 and the shipped defaults.
- **BD-Q2, anchor at the request:** adds the principal's reaction time,
  costs late stakes latency, and buys no cover.
- **BD-Q2, anchor at `h_f`, or at `spendable_height + REF_ANCHOR_AGE`
  alone:** the funding is not sweepable until the sealed P-scan covers it
  (`h_f + 720`), so every draw of a window up to 720 collapses onto that
  point, a public offset from the observer's anchor.
- **BD-Q3, re-anchor a never-sent post only at `REBUILD_AT`:** a restart
  below 50 blocks sends a non-canonical reference age and a shorter
  lifetime.
- **BD-Q2, the least-spendable output as the anchor:** under-delays the
  newest funding transfer of a multi-input bond.
- **BD-Q2, a fresh draw for a late request:** latency with nothing the
  observer can use.
- **BD-Q3, sign at the request:** the defect (§1.2).
- **BD-Q3, cap the offset at 94 and keep signing at the request:** every
  post lands, but the reference age stays `offset + 6`, which the daemon
  checks and the transaction names.
- **BD-Q3, re-sign a sent post (at `REBUILD_AT` or once `proof_expired`):**
  it moves the end date, so a post a censoring daemon never lands re-signs
  forever, and it is the only source of two live versions with the same
  key images.
- **BD-Q3, release a submitted record on a terminal verdict:** the daemon
  holds valid bytes from the first submit and can relay the bond after the
  release, landing it for a dropped slot.
- **BD-Q3, a fresh draw when re-staking after `expired`:** the first
  broadcast already showed the post time; a second delay only adds latency.
- **BD-Q5, wire the floor with the window (`due = a + SEB + s`):** an epoch
  of latency for no cover.
- **BD-Q5, the floor alone:** a constant offset from the funding, no cover.

---

## 4. Attacker objectives (rule 26 A3)

| Objective | Route |
| --- | --- |
| **O1.** Link principal to `P` from the funding broadcast (network origin, forward). | BD-Q4: the window is sized against it, with the default posture's vantage as input 1. |
| **O2.** Read the request height, or the funding block, off the bond's reference. | BD-Q3: absorbed. The reference age at broadcast is 6. |
| **O3.** Keep a dead post resending and the funds reserved. | Absorbed: signed at due; one version (Rule 1); it ends at its end date (WR-Q3). |
| **O4.** Tie the post's send to the wallet opening, when the due fell while the wallet was closed. | Discipline note. Today's sealed post sends at reopen too. Whether the post rides the serving-launch standoff (`engine/stake_timing.rs:206`, SH-2b-2) is posed in the implementation slice. |
| **O5.** Fingerprint wallets by window cohort after a window change. | BD-Q4: the window is fixed at genesis. |
| **O6.** A remote daemon (no own node) receives both the funding transfer and the bond post from one client. | No window helps: it sees the post submitted. Conceded under the own-node posture (`engine/transaction_submitter.rs:479-483`). The routes are the principal-side Tor flip (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:1988`) and the per-`P` submit posture (2d-2). Recorded, not absorbed. |
| **O7.** A malicious daemon reports a terminal verdict to make the wallet release its reservation and drop the slot while the bond can still land. | Absorbed by Rule 2: no daemon verdict releases a submitted record; the chain decides at the end date. |
| **O8.** Censor or falsely reject the post to deny the stake. | Bounded, not absorbed: one window per attempt, surfaced at once as the `in_flight` state `refused` (or `expired` past the end date) and at the end date as the outcome `rejected` or `expired`, each with `funds_return_at`. The route is the own-node posture (O6). Repeated denial costs the user latency, never funds. |

---

## 5. The implementation slice

**Its work** (BD-Q2, BD-Q3, the BD-Q5 deletion):

- The planned state and the schema bump: the posture, the draw `s`, one
  `reference_height` and the recorded terminal verdict (`TerminalErrorKind`)
  per record, shared with or following WR-Q2/WR-Q3's v13.
- The anchor and the due (BD-Q2), on the daemon-claimed count clock.
- Assembly, proof and signature at the due tick inside the actor, sealed
  before the first send (BD-Q3).
- Rule 1 in the dispatch driver: the send recorded before the submit
  call, and no re-sign after it.
- Rule 2 in the dispatch driver: the terminal arm
  (`engine/pscan/dispatch.rs:794-803`) stops sending and keeps the record
  and the reservation.
- **Rewrite the shipped `STAKING_UNAVAILABLE_ON_THIS_DAEMON` sentence**
  (`engine/pscan/dispatch.rs:53-56`). Its "its funds are spendable
  again" is false under Rule 2: the funds return at `funds_return_at`.
- The BD-Q5 deletion (`MIN_COLD_START_SPACING`, `EconomicSpacing`,
  `SebSpan`), with the drifted citation at `engine/stake_timing.rs:160-163`
  and the 2C2B inventory of landed types
  (`ARCHIVAL_BOND_REQUEST_2C2B_PLAN.md:379-385`, `:580`).

The exit, claim and drain changes of the WR-Q3 amendment are the
wallet-RPC slice's (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q4).

**Its tests:**


- A post due at count `a + 1 + s` is signed at its first send and carries
  reference age 6 (it replaces the ignored test, `engine/pscan/dispatch_tests.rs:1293`).
- A never-sent sealed post whose reference is no longer canonical is
  re-signed before its first send at reference age 6, including after a
  restart ten blocks later (below `REBUILD_AT`).
- A sent post is resent unchanged to its end date and is never re-signed;
  at the end date the record ends `expired` and the reservation is
  released.
- A crash between recording the send and the submit call leaves the
  record treated as sent.
- A terminal verdict stops sending and keeps the record and the
  reservation. Its `in_flight` state is `refused` with the reason and
  `funds_return_at` until the end date, then `expired` with the same
  reason; at the release the outcome is `rejected` with the reason.
- A post that lands after a terminal verdict takes the confirmed path.
- Re-staking after `expired` posts on the first tick, with no draw.
- **Instant staker, at production depth:** a funding output found by the
  P-scan at its 720-block horizon anchors at `a = h_f + 720`; a request at
  `a` produces a post at `a + 1 + s` with `s` drawn in full over `[0, W]`,
  and its reference height is not `h_f + 714`.
- **Restart between request and due:** the plan reloads, `s` is unchanged,
  and the post assembles from the re-derived bundle.
- **Elapsed age:** a request past count `a + 1 + s` posts at the next tick,
  with no added draw.
- **Multi-input:** the anchor is the latest `a` among the reserved
  outputs.
- **Schema:** the version bump and snapshot, and a v12 seal failing closed.
- **No dead code:** `rg -n 'MIN_COLD_START_SPACING|EconomicSpacing|SebSpan' rust`
  returns nothing.

---

## 6. What passes to the wallet-RPC round

The wallet-RPC round is ruled (`WR-Q1…WR-Q5`, merged in #1079) and not yet
built. Each carry below is recorded in both documents (rule 26 A5);
`WALLET_RPC_STAKING_OUTCOMES.md` §1.1 points here.

- **The FOLLOWUPS row** "The bond-post delay does not decorrelate the
  funding transfer from the bond" is owned by this round.
- **WR-Q1 (`in_flight`).** A planned, unsigned stake is "sealed, not yet
  sent", so it fits the ruled `pending` state. No new state is needed
  unless BD-Q4's width forces one.
- **WR-Q3 (release at the end date).** The end date is `reference_height
  + MAX_AGE`, written at assembly, one `reference_height` per record (the
  shared v13 field): under Rule 1 a sent record has one version. A planned
  stake has no reference until it is signed at due, so it cannot expire
  before then. Two cases need WR-Q3's rule:
  - **A plan that cannot be signed at due**: funding spent elsewhere, or a
    posture refused. It needs an outcome (WR-Q2) and a release.
  - **Withdrawing a plan by dropping the record.** No byte of it was ever
    sent, so no bond can land later. That removes both objections WR-Q3
    makes to freeing the inputs ("removes the pending record while a bond
    can still land") and to cancelling by spending (a fee and an on-chain
    linkage event). Whether the owner may withdraw a plan is WR-Q3's to
    rule.
- **The WR-Q3 amendment (Rule 2), recorded in both documents.** No daemon
  verdict releases a submitted record of any kind; every submitted record
  ends at its end date. While a record that saw a terminal verdict can
  still land, its `in_flight` state is `refused` (then `expired` past the
  end date, with the `reason` kept). `rejected` is only the outcome: a
  terminal verdict was seen and a record holding reserved inputs reached
  its end date without landing; its funds are `returned` and the reason
  sentence stays. A record with no reserved inputs, the Q11 zero-fee
  claim, ends `ended_unconfirmed` instead, keeping the reason. Per kind, at source: the stake
  and the exit release on a daemon verdict today and change; the claim and
  the drain already do not (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q4).
- **WR-Q5 (what the response reveals).** The wire carries no due count,
  and a `pending` entry says nothing about when it will be sent. If BD-Q4
  rules a window far above `600`, the user waits up to that long with no
  date; whether the owner then sees a post-by bound is WR-Q5's to reopen.

---

## 7. What this round does not do

- No code in this PR. The implementation slice (BD-Q2, BD-Q3, the BD-Q5
  deletion) is next and does not wait for BD-Q4.
- It does not choose the launch-window rate cap (BD-Q4, "Launch").
- It does not build the principal-side Tor default flip
  (`ARCHIVAL_BOND_WI4_MEASUREMENT.md:1988`).
