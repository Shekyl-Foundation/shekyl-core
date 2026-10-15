# Wallet RPC — staking outcomes a user can see: Round 0

**Status:** OPEN — Round 0, questions **POSED 2026-10-15**; nothing is
ruled. Each question carries a default, its reason, what the alternative
changes, and a falsifier. **No code until the questions are ruled.** One
dependency on the bond lane is open (§1.1).

**Ground:** `shekyl-core` `dev` at `a0d3ebcb1` (the #1076 merge, after
#1075), with the daemon RPC at `CORE_RPC_VERSION` 3.54 (#1057). Every
`file:line` below was read at that commit.

**Identifier family:** `WR-Q1…WR-Q5` (the questions), registered in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 at birth. The
round extends `WI-RPC-1`'s `staking_info` and adds nothing to any other
family.

**The bar:** failure modes are first-class
([`82-failure-mode-ux`](../../.cursor/rules/82-failure-mode-ux.mdc)); a
user needs no protocol knowledge to act on what they see
([`81-no-protocol-knowledge`](../../.cursor/rules/81-no-protocol-knowledge.mdc));
absence is not a value
([`43-absence-is-not-a-value`](../../.cursor/rules/43-absence-is-not-a-value.mdc)).

---

## 1. The gap

A stake, an emission claim, a drain and an exit each become a durable
pending record before any byte is sent. Each record holds a funding
reservation while it lives. The user sees none of these records.

**What the wallet RPC reports today.** `staking_info` returns:

- whether staking is enabled;
- the staked balance;
- the staked-output count;
- the P-scan frontier;
- `recovery_pending_reopen`;
- the serving posture and the serving-priority count.

See `StakingInfoResult`, `rust/shekyl-wallet-rpc/src/types.rs:785-827`.
The response type is built in two places, `staking.rs:76-86` and
`queries.rs:289-300` (`get_wallet_info`'s `staking` block). Any change
below changes both.

Nothing in `staking_info` names a record in flight, refused or stuck:

- **A refused stake** drops `bonded_principal_pending` back to zero and
  writes one log line.
- **A stuck stake** changes nothing the RPC shows.
- **Ordinary sends already have this.** `SendState::TerminalRejected` is
  projected through the transfer queries (`project.rs:197`,
  `queries.rs:547`). Pending records never pass through that journal.

### 1.1 Dependency: a bond post is signed long before it is sent — OPEN, the bond lane's decision

**What the code does.**

- The post is assembled and signed at `anchor_t0`, the daemon's claimed
  tip (`engine/bond_orchestrator.rs:555-557`).
- Its reference is `min(ledger synced height, curve-tree ingested tip) −
  REF_ANCHOR_AGE` (6) (`bond_orchestrator.rs:455-461`). So the reference
  is at most `anchor_t0 − 6`.
- It is first sent at `anchor_t0 + bond_post_offset_blocks`. The offset
  is drawn uniformly over 0 to 600 inclusive
  (`engine/stake_engine/actor.rs:154-170`; `shekyl-standoff/src/draw.rs:31-36`,
  `:80`, `:96-98`). The guard keeps the first draw of a distinct pair
  and discards the second, which only probes the entropy source
  (`engine/stake_engine/helpers.rs:455-463`, `:487-503`), so the offset
  stays uniform.
- Both daemons refuse a reference older than
  `FCMP_REFERENCE_BLOCK_MAX_AGE` (100): `src/cryptonote_core/blockchain.cpp:3615-3621`
  and `shekyl-chain-rules/src/rules/tx_against.rs:320-324`. A proof built
  at the canonical anchor stays submittable for `PROOF_VALIDITY_HORIZON`
  (94) blocks (`shekyl-curve-tree/src/reference.rs:95-106`).

**What follows.**

- **Most posts are dead on arrival.** Any offset over 94 sends a
  reference already past the window. That is 506 of the 601 equally
  likely offsets, about 84 %.
- **The answer is not final.** The Rust daemon answers a too-old
  reference `StaleRoot` (`shekyl-daemon-rpc/src/submit/engine.rs:374`).
  The wallet classes `StaleRoot` as retryable
  (`engine/transaction_submitter.rs:270`), so the driver resends the same
  bytes on every due tick until the 900-block alarm
  (`pscan/dispatch.rs:820-839`, `:601-610`).
- **Posts that do land are fingerprinted.** `REF_ANCHOR_AGE` is
  privacy-canonical, so that "the on-wire reference age does not
  fingerprint the wallet" (`reference.rs:75-84`). A post sent `offset`
  blocks after signing carries reference age `offset + 6` instead of 6.
  The post stands apart from an ordinary send, and its reference age
  shows every node the drawn offset.
- **Today the C++ daemon hides all of this.** It answers every kind-5
  JoinMarket post `JoinMarketUnsupported` before any reference check
  (the FOLLOWUPS row "The five bonded regtest walks are decided dark…").
  The defect appears at `DEL-008`.

**Confirmed by a dispatch unit test (a probe, not committed).** A post
with offset 300:

- is not sent one block before it is due;
- at its first send, carries a reference whose age is at least 306,
  against a `MAX_AGE` of 100;
- answered `StaleRoot` each time, is resent with identical bytes at every
  tick until `at + 900`;
- then stops, with the record held as `Dispatched` and nine attempts
  counted.

**The decision is the bond lane's.** The two shapes:

- **Sign at the due time.** The reference age is the canonical 6 at
  broadcast, and the offset stays private. But assembly moves to the
  due tick, where the secrets must be re-derived inside the actor:
  `CB-2`'s seed discipline (`EMISSION_CLAIM_BUILDER.md`, "CB-2
  no-seed-re-borrow").
- **Bound the offset to the proof lifetime.** This keeps one signing at
  `anchor_t0`, but shrinks the decorrelation window from 600 to 94
  blocks, and the reference age still shows the offset.

**How this round depends on it.** The expiry mechanism of WR-Q3 works
under either shape. It needs only each record's reference height, and it
also covers the defect as it stands. Until the bond lane decides, most
stakes on the Rust daemon would end as `expired`, and the reason sentence
must not blame the user.

---

## 2. What happens to each kind today

The four kinds live in one sealed block, `PendingPostBlock`
(`shekyl-engine-state/src/pending_post_block.rs:394-437`), version 12
(`:94`). Every kind shares one state type, `PendingPostState`
(`:113-130`): `Pending`, or `Dispatched { at, attempts }`.

- `at` is a **chain count**, not a height: the claimed count the
  due-check fired against (`:119-122`).
- There is no `Confirmed` arm. Confirmation removes the record, and the
  reservation goes with it (`:100-103`).

| Kind | Record | Sent by | Terminal rejection | Ambiguous or retryable (`StaleRoot` included) | Past the horizon |
| --- | --- | --- | --- | --- | --- |
| Stake (bond post) | `PendingBondPost` (`:138-177`) | the dispatch driver, every sweep tick (`pscan/dispatch.rs:521-842`) | record removed, reservation released, one log line (`dispatch.rs:794-819`) | resent byte-identical on the next due tick (`:820-839`) | resends stop; one log alarm per session (`:601-610`, `:719-735`); record and reservation held |
| Emission claim | `PendingEmissionClaim` (`:209-224`) | the claim seam, once (`claim_dispatch.rs:422-435`) | **held**: any submit failure leaves the record live | held; never resent | one log alarm per session (`dispatch.rs:566-599`, `:696-717`); held |
| Drain | `PendingDrain` (`:252-266`) | the drain seam, once (`drain_dispatch.rs:255`) | **held** | held; never resent | as the claim |
| Exit (`Release`) | `PendingRelease` (`:296-309`) | the release seam, once (`release_dispatch.rs:655-669`) | **removed at the seam** on a definite first-send `RejectedTerminal` (`:304-310`, `:633-669`; #601) | held; never resent (`:728-736` pins `StaleRoot` as held); the user already sees `-29522 UNSTAKE_FATE_UNKNOWN` from `unstake` (`shekyl-wallet-contract/src/error.rs:339`) | as the claim |

**Every kind carries a reference, and none re-proves.**

- All four are FCMP++ spends anchored `REF_ANCHOR_AGE` behind the
  wallet's tip:
  - the stake and the exit through `anchored_reference_block`
    (`bond_orchestrator.rs:443-461`; `release_dispatch.rs:503-506`);
  - the drain "exactly as a bond post is" (`drain_dispatch.rs:20-24`);
  - the claim through `claim_reference_height`
    (`claim_orchestrator.rs:25-30`).
- No kind rebuilds its proof after sealing. The stake resends the same
  bytes; the other three send once and hold.
- So every record has an **end date**: `reference_height +
  FCMP_REFERENCE_BLOCK_MAX_AGE`, inclusive. After it, no block on any
  chain can include the transaction.
- The transaction carries its reference as a block hash
  (`rv.referenceBlock`, resolved to a height at `blockchain.cpp:3600-3601`).
  Assembly has the height in hand (`reference.height`,
  `release_dispatch.rs:506`) but does not store it.

**The horizon.** `DISPATCH_ALARM_HORIZON_BLOCKS` is 900: the reorg-deep
confirmation floor (720) plus 25 % (`dispatch.rs:185-216`). It bounds how
long the driver waits for a confirmation before it alarms. It is not the
end date, and it says nothing about whether the transaction can still
land.

**Alarm memory.** Both alarm-once sets are in memory only, and a restart
re-raises them (`dispatch.rs:428-436`). So is the set that holds
resubmits after a successful broadcast (`:427`, `:777-781`). None of them
can be the source of a reported state.

**Where the one prune slot sits.** Claims and drains have no
terminal-reject prune. The driver's comment calls the log line "the
honest half-measure while terminal-reject prune is a separate slice"
(`dispatch.rs:566-573`). The slot that prune will fill is leg 4 of the
cadence driver:

- registered and invoked each tick with an empty body
  (`engine/cadence/mod.rs:172-175`);
- described in `ENGINE_CADENCE_DRIVER.md:331-342`;
- owed in the FOLLOWUPS row "Drain/claim/release dispatch driver —
  terminal-reject prune + byte-identical resubmit remain", which marks
  the prune a security item and says never to land resubmit alone. Its
  security note names the reference age window as "the only other bound"
  on the replay channel.

### 2.1 Findings at source

- **The cause type.** The cause the dispatcher holds is the engine's
  `TerminalErrorKind` (`engine/error/submit.rs:34`). `RejectCause` is the
  daemon reply's type (`shekyl-rpc-types/src/lib.rs:205`); the wallet
  contract has no reject-cause type.
- **The exit is the one kind pruned at its seam.** A definite first-send
  refusal removes it (§2's table). Claims and drains are held.
- **The pool's three-day clock is per node, from that node's admission.**
  `CRYPTONOTE_MEMPOOL_TX_LIVETIME` is three days
  (`src/cryptonote_config.h:104`), about 2,160 blocks at 120 s. Age is
  measured from `receive_time` (`src/cryptonote_core/tx_pool.cpp:1080`).
  A byte-identical resend to a node that still holds the transaction does
  not reset it. Only re-admission after eviction, or a relay-method
  upgrade, does (`tx_pool.cpp:498-512`). The pool is not what ends a
  transaction; its reference window is (§2).
- **The dispatcher's clock is not one the RPC has.** The driver judges
  against the sweep's claimed daemon count (`pscan/task.rs:435-437`).
  `staking_info` reads only sealed files (`engine/staking_read.rs:417-450`).
- **The scan frontier is already reorg-deep.** The P-scan's ingest
  ceiling trails the tip by `ARCHIVAL_REORG_DEPTH_BLOCKS`
  (`config/consensus_constants.json:26`); its sealed frontier is
  `PScanState::synced_height` (`shekyl-engine-state/src/pscan_state.rs:481-484`).
- **The response type's contract has drifted.**
  - `pscan_synced_height`: documented as `null` in Rust
    (`types.rs:792-797`), as absent in `wallet_rpc.yaml:2813-2818`, and
    omitted by the code.
  - `recovery_pending_reopen`: a Rust field with `serde(default)`
    (`types.rs:801-802`), and **missing from `wallet_rpc.yaml`
    altogether**.

---

## 3. Questions

### WR-Q1 — What does `staking_info` report about records in flight?

**Default.** `staking_info` gains a required field `in_flight`: a list,
one entry per live pending record, in no meaningful order.

- **`kind`**: `stake`, `claim`, `drain` or `exit`.
- **`state`**, one of:
  - `pending`: sealed, not yet sent;
  - `dispatched`, with `dispatched_at_height` and `attempts`;
  - `expired`, with `funds_return_at`: the end date has passed, so the
    transaction can never be mined. The funds are still held until the
    staking scan reaches `funds_return_at`, which is the end date itself
    (WR-Q3). It is a scan height, comparable with `pscan_synced_height`
    in the same response;
  - `stalled`: reachable only in the two cases below.
- **No per-record handle.** See WR-Q5.

An empty list means nothing is in flight. No field is absent or `null` to
mean that (rule 43). A new required list is still additive for a reader
that ignores unknown keys; a reader that refuses unknown keys must update
in the same change.

**Every arm comes from sealed state.** `pending` and `dispatched` are the
record's `PendingPostState`. `expired` is computed from the record's
durable reference height (WR-Q3) against a clock (sub-question (a)). No
state is read from the in-memory alarm sets (§2), so each one survives a
restart, which the log alarm does not.

**Where `stalled` remains reachable.** If WR-Q3 and WR-Q4 are ruled as
posed, every kind ends by confirmation, rejection or expiry, except in
two cases where the scan cannot tell whether the record landed (WR-Q3,
"How each kind counts as landed"):

- **A partly spent reservation.** A claim, drain or exit past its end
  date whose reserved inputs are **partly** spent. The record's own
  transaction spends all of its inputs or none, so a part spent means
  another transaction spent some. The reservation stall alarm already
  names this anomaly (`dispatch.rs:696-717`).
- **An empty reservation.** The Q11 zero-fee emission claim holds no fee
  inputs, so `remove_settled` never settles it
  (`pending_post_block.rs:987-1001`), and nothing else shows whether it
  landed (the FOLLOWUPS row "Q11 zero-fee-input emission claim has no
  settlement evidence"). Releasing it as `expired` could report a claim
  that was in fact mined.

Default for both: hold the record, report `stalled`, and keep the alarm.
Releasing the unspent rest of a partial reservation, or the empty claim
once a claim-match observation exists, is a separate question.

If WR-Q4 is ruled (b), `stalled` stays reachable for every claim, drain
and exit past the 900-block horizon, as today.

**Sub-question (a), the clock.** `expired` begins when the tip passes the
end date. The dispatcher's clock is the sweep's claimed count, which the
RPC does not read. (`funds_return_at` needs no clock; it is a frontier
height, WR-Q3.)

| Candidate | Disagrees with the dispatcher by | Cost |
| --- | --- | --- |
| **The wallet ledger's synced height**, the one `get_wallet_info` reports (`queries.rs:258-259`) — **default** | the gap between two reads of one daemon's claimed tip on two cadences: about one sweep interval | none; already read under the same guard in `get_wallet_info` |
| The sealed P-scan frontier (`pscan_synced_height`) | the reorg depth: the frontier trails the tip by 720 blocks (§2.1) | none, but `expired` would appear 720 blocks late |
| A persisted last-tick count in the pending block | none | a schema bump, and a seal on every tick |
| A daemon read inside `staking_info` | none at read time | a network call in a read-only method that today makes none |

**Sub-question (b), naming.** `at` is a `ChainCount`
(`pending_post_block.rs:119-122`). A wire field named `…_height` that
carries a count is the bug class `HEIGHT_SEMANTICS.md` exists to stop.

- Default: convert to the tip height, `count − 1`, and name it
  `dispatched_at_height`. Every other height on this response is a
  height, `funds_return_at` included.
- Alternative: carry the count and name it `dispatched_at_count`.

**Sub-question (c), closed or open strings.** The contract already
rejects a closed response enum for `posture`, because an older validator
would refuse the whole `staking_info` reply over one display field
(`wallet_rpc.yaml:2830-2842`).

- Default: `kind` and `state` are open strings with documented values,
  for the same reason.
- Alternative: closed enums. A new kind or state would then break every
  older client's balance reading.

**Sub-question (d), the existing rule-43 breaches.** Default: fix both in
the same change, because they sit in the same response type.

- `pscan_synced_height` becomes required and `null` when the wallet has
  never scanned as a staker. "Never scanned" is an answer, not something
  withheld.
- `recovery_pending_reopen` loses `serde(default)` and is added to
  `wallet_rpc.yaml` as required.

**Cost of the default.** Both tighten existing fields, which goes beyond
additive. A Rust reader built from the new type refuses an older wallet
RPC's reply: one that omits `pscan_synced_height` or
`recovery_pending_reopen`. Wallet RPC and its clients ship together
pre-genesis, so the cost falls on mixed builds only.

The alternative is to name them in FOLLOWUPS against `WI-RPC` and leave
them.

**What the alternative changes.** A per-slot field that is absent when
idle is the shape rule 43 forbids. It also puts slot ordinals on
`staking_info`, which WR-Q5 argues against.

**Falsifier.**
- A `staking_info` reply with no `in_flight` key, or with `null` in its
  place, must fail to decode.
- A test seals a `Dispatched` record with reference height `r`, advances
  the ledger clock past `r + 100`, restarts the engine, and reads
  `expired` with `funds_return_at == r + 100`.
- `rg -n 'alarmed_this_session|alarmed_reservations' rust/shekyl-wallet-rpc`
  must return nothing.

### WR-Q2 — How is an ending reported, when the record is gone?

Today removal is the whole effect (`dispatch.rs:799-803`). Nothing durable
remains to report, and dispatch runs on a background tick, so no RPC call
is waiting for the answer.

**Default.** The pending block gains one durable **last outcome** per
`(kind, persona)`, the key every pending record set already uses,
scoped as WR-Q4 rules. `staking_info` reports these as a second
list, `outcomes`, each entry with:

- **`kind`**;
- **`outcome`**: `rejected` (a terminal verdict) or `expired` (the end
  date passed and the scan has made it final, WR-Q3);
- **`reason`**: a user sentence, never an enum name (rule 81).
  - For `rejected`, chosen from `TerminalErrorKind`. The table starts
    from the sentence already shipped for one cause,
    `STAKING_UNAVAILABLE_ON_THIS_DAEMON` (`dispatch.rs:53-56`). Every
    other kind gets a row before the commit lands.
  - For `expired`, one sentence that does not blame the user, because
    under §1.1 the cause is usually the wallet's own timing: for example,
    "The stake was not accepted in time and has been withdrawn. Its funds
    are spendable again."
- **`at_height`**: the tip height when the outcome was written;
- **`funds`: `returned`** — true by construction, since removal is the
  release.

**How it is written.** The outcome is written in the same `mutate`
closure that removes the record (`dispatch.rs:800-802` for a rejection;
the expiry release of WR-Q3 for an expiry): one seal, so the two cannot
disagree after a crash. The removal-ordering contract
(`pending_post_block.rs:105-112`) is unaffected. A rejected post never
carries a match, and an expired one cannot gain one (WR-Q3).

**How it is cleared.**
- Cleared by the next successful seal of the same kind for the same
  persona.
- Or cleared by an explicit `acknowledge_staking_outcome { kind }`, which
  acts on the active persona as every staking action does (WR-Q5).
- **What the no-handle default costs here.** An outcome for a persona
  that is not active shows in `outcomes`, but no call can acknowledge it;
  only that persona's next seal of the same kind clears it. This is the
  case WR-Q5's opaque-handle alternative exists for.

**Cost.** A persisted change: `PENDING_POST_VERSION` 12 → 13,
refuse-not-migrate, schema snapshot (rule 42), shared with WR-Q3's
reference-height field. A v12 file is refused and re-assembled, as every
earlier bump was.

**Alternative.** Report the outcome only in the response of the call that
triggered it. This fails for the stake: dispatch is a background tick and
no call is waiting. It works for the exit's first send, which already
does it (`-29522` and the seam's synchronous refusal).

**Falsifier.** The armed tripwire
`e2e_the_cxx_daemon_answers_join_market_unsupported`
(`engine/regtest_e2e.rs:3481`) already drives a terminal rejection end to
end against the real C++ daemon. Extend it: after the rejection,
`staking_info` shows `outcomes[0].outcome == "rejected"` for
`kind == "stake"`, `reason` is the shipped sentence,
`funds == "returned"` and `in_flight` is empty. After a restart it still
does.

### WR-Q3 — How does a stake that will never land end?

**Default: automatic expiry release.**

- A record's **end date** is `reference_height +
  FCMP_REFERENCE_BLOCK_MAX_AGE`, inclusive (§2).
- Once the staking scan's sealed frontier reaches the end date, the
  record is removed, and its reservation with it. The frontier already
  trails the tip by `ARCHIVAL_REORG_DEPTH_BLOCKS` (720): the sweep
  ceiling is that far behind (`pscan/start.rs:93-95`), so every block at
  or below it is final under the wallet's own model. `funds_return_at`
  is the end date.
- An `expired, funds returned` outcome (WR-Q2) is written in the same
  atomic save.
- The release runs in the dispatch tick, which already holds the scan's
  accrual (`pscan/task.rs:426-437`). It runs last in the tick's one
  `mutate` pass (`dispatch.rs:539`), after both retires, so a record that
  did land leaves as landed first (below).
- **Fee:** none. **Finality:** by construction. **User action:** none.

**Why the phantom-slot cleanup is then safe.**

The cleanup (`engine/stake_persist.rs:187-231`) drops a bonded slot when
covered scan evidence shows no bond and no pending record bridges it. It
is airtight only while no real bond can be missing from the evidence.

- No block above the end date can include the post: both daemons refuse
  a reference older than `MAX_AGE` (§1.1).
- Every block at or below the end date is inside the sealed frontier,
  which is itself reorg-deep (§2.1). It was scanned with the persona
  watched, since the pending record kept it live.
- So if the post landed, the scan holds its match, the confirmation
  retire ran first, and the record left as confirmed. If it did not, no
  bond exists and none can.

A slot the cleanup drops after the release is a stake that never
happened. That is the case the cleanup exists for.

**How each kind counts as landed before expiry.** Both retires and the
expiry read the same evidence: one accrual, one frontier, one reorg depth
(`pscan/task.rs:426-437`).

| Kind | Landed means | Retire | Runs before expiry |
| --- | --- | --- | --- |
| Stake | the scan holds a reorg-deep JoinMarket match for the persona | `remove_confirmed` (`dispatch.rs:549`) | yes, same pass |
| Claim, drain, exit | every reserved input is gone from the scan's live funding set | `remove_settled` (`dispatch.rs:561`; `pending_post_block.rs:1003-1043`) | yes, same pass |

At expiry the frontier is at or past the end date, and a record's
transaction can only have landed at or below it. So if it landed:

- a stake's match is inside the frontier, and `remove_confirmed` has
  already removed it;
- a claim's, drain's or exit's inputs were spent inside the frontier, are
  gone from live funding, and `remove_settled` has already removed it.

What reaches expiry has every reserved input still live, which means it
did not land. Two cases reach neither branch, and they stay `stalled`
(WR-Q1): a reservation **partly** spent (another transaction spent some
of its inputs), and the **empty** reservation of the Q11 zero-fee claim,
which `remove_settled` never settles and which expiry must therefore not
release.

**Sub-question (a), how the reference height becomes durable.**

- **Default:** a new field, `reference_height: BlockHeight`, on each
  pending record that WR-Q4 brings under expiry. It is written at
  assembly, where the height is already in hand (`reference.height`).
  Schema v12 → v13, refuse old files (rule 42), shared with WR-Q2.
- **Alternative:** recover it from `tx_bytes`. The transaction carries a
  block **hash** (`rv.referenceBlock`), so this parses the RCT section on
  every tick and resolves the hash through the wallet's own chain view.
  That view can reorg or prune, so it can fail to answer, and an
  unanswerable end date would hold funds forever. No schema change.

**Sub-question (b), the finality margin.**

- **Default:** `frontier ≥ end date`. The safety argument above needs
  every block at or below the end date to be final and scanned, and a
  frontier at the end date already gives both, since it trails the tip by
  720. The funds return when the tip is about `end date + 720`, roughly a
  day after the end date.
- **Alternative:** `frontier ≥ end date + 720`. This counts the same
  margin twice and holds the funds about a day longer. It buys protection
  only against a reorg deeper than the wallet's finality model, which
  that model rules out everywhere else.

**Sub-question (c), stop dead re-sends.** A bond post answered `StaleRoot`
past its end date is an expiry, not a retry.

- **Default:** the driver sends nothing whose end date has passed. There
  is no first send if the post is due after its end date (under §1.1,
  most are), and no resend after it.
- **Why:**
  - Every such send is wasted traffic.
  - It is an observable pattern: one origin re-offering the same dead
    bytes on every tick until the 900-block alarm.
- **What follows for the horizon:** the 900-block alarm horizon then no
  longer governs bond posts, since their end date always comes first.
  Its bond-post use retires (rule 15). The operator signal becomes the
  `expired` outcome.

**Wargames.**

| Case | Outcome |
| --- | --- |
| The post lands late | It can land only at or below its end date. The scan matches it before the frontier passes the end date, and the confirmation retire removes the record as a confirmed stake. Expiry never fires |
| A reorg near the end date | The release waits for a frontier that is itself reorg-deep. A reorg within that depth changes nothing; one deeper is outside the wallet's finality model everywhere |
| The consensus age limit changes | The end date is `reference_height + FCMP_REFERENCE_BLOCK_MAX_AGE` read **now**, while the record was signed under the limit in force **then**. A **raised** limit makes the computed end date too early: the wallet would release, and let the phantom-slot cleanup drop, a bond that can still land. That is the stuck-funds case the cleanup exists to prevent. A **lowered** limit only holds funds longer. The limit is a consensus constant (`config/consensus_constants.json:5`); raising it makes a different chain. The sentinels that pin it today sit in other modules (`reference.rs:69`, `tx_against.rs:71`) and say nothing about this one. See the invariant below |
| A hostile node holds the bytes and broadcasts them later | After the end date, every daemon refuses them for their reference age. Before it, they can land only as the user's own stake, which the scan retires as confirmed |
| The scan stalls | The frontier does not advance, the funds are not returned, and the state stays `expired` with its `funds_return_at`. Nothing is released early |

**Invariant: the end date assumes the age limit never rises.**

- **Default:** the expiry module carries its own compile-time sentinel,
  `FCMP_REFERENCE_BLOCK_MAX_AGE == 100`, whose message names this round
  and says what raising the limit breaks. A test next to it fails if the
  limit changes without the module being revisited. Changing the limit
  then fails the build here, beside the sentinels that already fail
  elsewhere.
- **Alternative, if the limit ever becomes per-era:** store the limit in
  force at signing beside `reference_height`, and compute each record's
  end date from its own limit. That adds a field the single-era chain
  does not need today (rule 21: reopen when a per-era limit is
  proposed).

**Rejected alternatives.**

- **Free the inputs at the 900-block horizon — REJECTED.**
  - It is never final: the horizon bounds waiting, not landing
    (`dispatch.rs:185-216`).
  - The user's next send becomes the transaction that loses a race.
  - It removes the pending record while a bond can still land. That
    record is the bridge that stops the phantom-slot cleanup from
    dropping a real bond, and a dropped slot can never be re-adopted
    (`stake_persist.rs:211-214`). The bond would sit on chain with no
    slot to serve or exit it.
  - Expiry gives the same release with none of these costs.
- **Cancel by spending the reserved inputs, through a `Cancelling` state
  arm — REJECTED.**
  - It costs a fee.
  - It is an on-chain linkage event: the cancel spends inputs whose key
    images the post already published, so it shows observers that a
    stake attempt was withdrawn.
  - It is unneeded: the reference window ends every post by itself, for
    free and with the same finality.

**Falsifier.**
- A sealed post with reference height `r` and a frontier below `r + 100`
  stays in `in_flight` as `expired`. A frontier at `r + 100` removes it,
  writes `outcomes[0].outcome == "expired"` in the same seal, and
  releases its gindexes.
- A drain whose inputs are all absent from live funding at that frontier
  is retired as settled, and no `expired` outcome is written. One with
  part of its inputs absent stays `stalled`. A zero-fee claim with no
  reserved inputs stays `stalled`.
- Changing `fcmp_reference_block_max_age` fails the expiry module's own
  sentinel.
- A post matched by the scan at or below `r + 100` is retired as
  confirmed, and no `expired` outcome is written.
- A due tick past `r + 100` sends nothing.
  `rg -n 'reference_height' rust/shekyl-engine-state/src/pending_post_block.rs`
  hits on each kind WR-Q4 brings under expiry.

**Blocked fixture.** No bond post can land on the C++ daemon, which
answers every kind-5 JoinMarket post `JoinMarketUnsupported` (the
FOLLOWUPS row "The five bonded regtest walks are decided dark…"). The
late-landing and expiry rows run against a real daemon at `DEL-008`. The
rejection path runs now, and it is WR-Q2's falsifier.

### WR-Q4 — Does one surface cover claims, drains and exits?

The kinds do not fail the same way (§2).

- **A stake** rejected terminally is removed.
- **An exit** rejected on its one send is removed at the seam.
- **A claim or a drain** rejected terminally is **held**, because the
  prune that would remove it is leg 4's empty body.

**Per kind, the reference and its `StaleRoot` handling (§2):**

| Kind | Carries an FCMP++ reference | On `StaleRoot` |
| --- | --- | --- |
| Claim | yes (`claim_orchestrator.rs:25-30`) | the seam returns the error; the record is held; never resent or re-proved (`claim_dispatch.rs:422-435`) |
| Drain | yes (`drain_dispatch.rs:20-24`) | as the claim |
| Exit | yes (`release_dispatch.rs:503-506`) | held; never resent or re-proved (`:728-736`) |

Each carries a reference, and none re-proves. So the end date of WR-Q3 is
also leg 4's missing proof: past it, the held transaction is dead,
whatever its verdict was.

**Option (a) — this round takes on leg 4's prune and resubmit.**
- Every kind gets a `rejected` outcome on a terminal verdict.
- **Cost:** the FOLLOWUPS row requires the prune to land together with
  byte-identical resubmit. The claim and drain seams must also persist
  the verdict, which they return to the caller and do not keep today.

**Option (b) — report what the state allows.**
- Claims, drains and exits appear in `in_flight` as `pending`,
  `dispatched` or `stalled`.
- `outcomes` gains them when leg 4 lands.
- **Cost:** a rejected claim or drain shows as `stalled`, and stays
  held, indefinitely.

**Option (c) — expiry release for every kind, in this round.**
- WR-Q3's mechanism applies to all four kinds: each record gets its
  `reference_height`, and each is released, with `expired, funds
  returned`, once the frontier reaches its end date.
- **Why it is safe to land alone:**
  - It is the prune half, by proof, and it adds no resubmit. So it keeps
    the FOLLOWUPS row's "never land resubmit alone".
  - The row's security note names the reference age window as the only
    other bound on the replay channel. Past the end date the retained
    copy cannot be mined by anyone, so pruning it then loses nothing.
- **What leg 4 keeps:** byte-identical resubmit within the lifetime, and
  an earlier prune on a definite terminal verdict.
- **Cost:**
  - the schema field on all four kinds (one v13 bump, shared);
  - a rejected claim, drain or exit holds its funds until about a day
    after its end date, then returns them. The outcome says `expired`,
    not `rejected`.

**Default: (c).** The end date changes the default. Every kind can now
end with a reported outcome and returned funds, and this round does not
take on resubmit, the half of leg 4 that is a security item. `stalled`
shrinks to the two cases of WR-Q1.

**The exit's "fate unknown" gets an end.** Today `unstake`'s
`-29522 UNSTAKE_FATE_UNKNOWN` has no way to resolve. Its message tells
the user the record is held "until it settles" and not to retry blindly
(`shekyl-wallet-contract/src/error.rs:945-949`). The contract adds that
the record waits for "the recovery slice (FOLLOWUPS dispatch-driver
prune+resubmit)" (`wallet_rpc.yaml:1344-1353`).

- Under (c) it resolves: by `funds_return_at`, `outcomes` holds a
  definite answer for the exit — landed (the exit settles), `expired`
  with the funds returned, or, for the partly spent anomaly, `stalled`.
- **Default:** the error's text and its contract entry say so in plain
  words, for example "Check `staking_info`: by the height it names, this
  exit will either have completed or been withdrawn with its funds
  returned." A user then has somewhere to look, and a time to look by
  (rule 82).

**Falsifier.**
- Under (c): a sealed, dispatched drain with reference height `r` reads
  `kind == "drain"`, `state == "expired"` once the clock passes
  `r + 100`, and leaves `in_flight` with an `outcomes` entry `expired`
  once the frontier reaches the release point.
- `rg -n 'reference_height'` hits on `PendingEmissionClaim`,
  `PendingDrain` and `PendingRelease`.

### WR-Q5 — What does the response reveal, and to whom?

**To whom.** The wallet RPC has no per-connection grant table. A caller
reaches it on a Unix socket protected by filesystem permission, or on TCP
behind HTTP basic auth or a loopback bind (`shekyl-wallet-rpc/src/auth.rs:6-10`).

- Every admitted caller holds every method. That is the same set that can
  already call `transfer` and `unstake`.
- The grants of `RPC_CHANNEL.md` §6.1 are the daemon's. The slice that
  puts the wallet RPC on the channel, RT-W12, is not authorized
  (`RPC_CHANNEL.md:1978`).
- Default: the new fields belong to whatever grant later holds staking
  state, if L1 ever gains per-connection grants. Until then, the audience
  is every admitted caller.

**What the list reveals.**

- **The count.** The list length is the number of records in flight, per
  kind. The code treats that count as `P`-activity volume and redacts it
  from `Debug` (`pending_post_block.rs:133-136`, `:390-392`, `:444`). For
  stakes it is already derivable from `staking_info`:
  `bonded_principal_pending` is that count times the bond floor
  (`staking_read.rs:236-251`). Claims, drains and exits are new.
- **Timing.**
  - `dispatched_at_height` reveals when the wallet first sent the record.
  - `funds_return_at` reveals the reference height, and so roughly when
    the record was built. For a sent record, every node that saw the
    bytes already knows that. For a stake that expired before it was
    sent (§1.1), it tells the caller when the wallet signed.
  - Default: acceptable for this audience, which is the wallet's owner.
    The alternative is to coarsen `funds_return_at` to the epoch.
  - The wire never carries `anchor_t0`, the offset or the due count. A
    `pending` entry reveals nothing about when it will be sent.
- **No persona.** Persona ids, transaction bytes and funding gindexes
  never reach the wire.

**No slots, no handles.**

- Slot ordinals are already on the wire through `get_staked_outputs`
  (`types.rs:770`). But every staking action refuses a `p_slot`
  parameter (`handlers.rs:393-403`), and `stake` says "the user never
  names a slot" (`lifecycle.rs:836-838`, rule 81).
- Default: no slot and no handle on these entries.
  `acknowledge_staking_outcome` acts on the active persona.
- Alternative: an opaque handle, random and persisted in the record at
  seal time, never derived from the persona or the bytes. It costs a
  schema field. It is needed only if a wallet must act on a record of a
  persona that is not active, which includes acknowledging that persona's
  outcome (WR-Q2).

**Linkage, said to the user.** A broadcast record publishes the key
images of its inputs to every node that saw it in a pool. When its funds
come back, any later spend of them links back to the attempt. Expiry adds
no transaction of its own, but it cannot undo what was published.

- Default: the `expired` and `rejected` outcomes for a record that was
  sent carry, in plain words: "Anyone who saw this attempt can link a
  later spend of these funds to it."

**Logs.** Nothing new is logged. The anomaly that stays `stalled`
already has its log alarm (§2).

**Falsifier.**
- `rg -n 'p_slot|persona|anchor_t0|offset|gindex' ` over the
  `in_flight` and `outcomes` wire types returns nothing.
- A decode test refuses an `acknowledge_staking_outcome` request carrying
  `p_slot`.

---

## 4. Proving it

The ruled shape is proved against a real daemon (regtest), not mocks.

- **Now:** the terminal rejection, end to end. The #1075 tripwire already
  drives it against the C++ daemon (WR-Q2's falsifier).
- **At `DEL-008`:** a dispatched stake, a late landing and an expiry all
  need a daemon that admits a kind-5 JoinMarket post. That is the Rust
  daemon at the cutover. The named blocker is the FOLLOWUPS row "The five
  bonded regtest walks are decided dark…", and the fixtures for those
  rows land with the walks it un-darkens. Until the bond lane settles
  §1.1, an expiry is what most stakes on that daemon will show.
- **Without a daemon:** the state projection (WR-Q1), the outcome write
  (WR-Q2) and the expiry release (WR-Q3) are tested against sealed state
  with a fixed clock and frontier. They are projections of durable state
  and need no network to be right.

## 5. What this round does not do

- No C++.
- No wallet-contract removal. `JoinMarketUnsupported` stays enumerated
  until `DEL-008` deletes it (the FOLLOWUPS row "The five bonded regtest
  walks are decided dark…").
- No change to when or how a bond post is signed. That is the bond
  lane's decision (§1.1).
- No byte-identical resubmit for claims, drains or exits. That stays
  leg 4's.
- No change to the dispatcher's resend policy or alarm horizon, except as
  WR-Q3 (c) is ruled.
