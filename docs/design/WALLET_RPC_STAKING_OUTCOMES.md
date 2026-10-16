# Wallet RPC — staking outcomes a user can see: Round 0, ruled

**Status:** RULED — Round 0 posed and ruled 2026-10-15 (Rick): WR-Q1…WR-Q5
accepted, with the amendments recorded in each ruling (§3). **No code in this
PR**; the rulings are implemented in a separately authorized slice. One
dependency on the bond lane is open (§1.1), recorded in FOLLOWUPS and posed
in the bond lane's Round 0 ([`ARCHIVAL_BOND_POST_DELAY.md`](ARCHIVAL_BOND_POST_DELAY.md)). One follow-on is not ruled here (§5).

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

### 1.1 Dependency: the bond-post delay does not decorrelate the funding transfer from the bond — OPEN, posed in the bond lane's Round 0

Recorded in `docs/FOLLOWUPS.md` as "The bond-post delay does not
decorrelate the funding transfer from the bond", owned by the bond lane's
Round 0, [`ARCHIVAL_BOND_POST_DELAY.md`](ARCHIVAL_BOND_POST_DELAY.md)
(`BD-Q1…BD-Q5`: the observers, the delay's anchor, signing at the due
time, the window, `MIN_COLD_START_SPACING`). It is blocked on that round's
rulings. Its §6 lists what it passes back to this round.

**What the code does.**

- The delay is measured from the stake request. The post is assembled
  and signed at that request, `anchor_t0`, the daemon's claimed tip
  (`engine/bond_orchestrator.rs:555-557`).
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
- **The reference reveals the signing time.** `REF_ANCHOR_AGE` is
  privacy-canonical, so that "the on-wire reference age does not
  fingerprint the wallet" (`reference.rs:75-84`). A post sent `offset`
  blocks after signing carries reference age `offset + 6` instead of 6.
  It shows every node when it was signed, which is the stake request,
  and so the drawn offset. The delay therefore does not hide the request
  it starts from.
- **The funding-to-bond spacing guard is unwired.** `MIN_COLD_START_SPACING`
  (one settlement epoch between the principal's funding transfer and the
  bond post) is `#[allow(dead_code)]`, "inert until cold-start spacing
  check is wired" (`engine/stake_timing.rs:192-203`).
- **Today the C++ daemon hides all of this.** It answers every kind-5
  JoinMarket post `JoinMarketUnsupported` before any reference check
  (the FOLLOWUPS row "The five bonded regtest walks are decided dark…").
  The defect appears at `DEL-008`.

**Shown by a dispatch unit test**, committed `#[ignore]`d with its
reason pointing at the FOLLOWUPS row:
`a_bond_post_sent_past_its_proof_lifetime_is_resent_unchanged_to_the_horizon`
(`engine/pscan/dispatch_tests.rs`). It asserts the defect, so it passes
while the defect stands and the bond lane's round inverts or replaces it.
A post with offset 300:

- is not sent one block before it is due;
- at its first send, carries a reference whose age is at least 306,
  against a `MAX_AGE` of 100;
- answered `StaleRoot` each time, is resent with identical bytes at every
  tick until `at + 900`;
- then stops, with the record held as `Dispatched` and nine attempts
  counted.

**Inputs to the bond lane's Round 0.** This round decides none of
them; they are what it found:

- **The delay's anchor.** It is measured from the stake request. The
  funding transfer is what the delay is meant to separate the bond from,
  and `MIN_COLD_START_SPACING`, the guard that measures from it, is
  unwired.
- **The window.** 600 blocks, against a proof lifetime of 94.
- **Signing at the due time.** The reference age at broadcast becomes
  the canonical 6 and stops showing when the post was signed. Assembly
  moves to the due tick, where the secrets must be re-derived inside the
  actor: `CB-2`'s seed discipline (`EMISSION_CLAIM_BUILDER.md`, "CB-2
  no-seed-re-borrow").
- **Bounding the offset to the proof lifetime.** One signing at
  `anchor_t0` is kept, but the window shrinks from 600 to 94 blocks, and
  the reference age still shows the offset.

**How this round depends on it.** The expiry mechanism of WR-Q3 works
whatever that round decides. It needs only each record's reference
height, and it also covers the defect as it stands. Until that round
lands, most stakes on the Rust daemon would end as `expired`, and the
reason sentence must not blame the user.

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

## 3. Rulings

Each question below states what Rick ruled on 2026-10-15 and what that
means for the code. The falsifiers are the acceptance tests the
implementation lands with.

### WR-Q1 — What `staking_info` reports about records in flight — RULED 2026-10-15

**Ruled.** `staking_info` gains a required field `in_flight`: a list,
one entry per live pending record, in no meaningful order.

- **`kind`**: `stake`, `claim`, `drain` or `exit`.
- **`state`**, one of:
  - `pending`: sealed, not yet sent;
  - `dispatched`, with `dispatched_at_height` and `attempts`;
  - `expired`, with `funds_return_at`: the end date has passed, so the
    transaction can never be mined. The funds are still held until the
    staking scan reaches `funds_return_at`, which is the end date itself
    (WR-Q3). It is a scan height, comparable with `pscan_synced_height`
    in the same response.
- **No per-record handle** (WR-Q5).

There is no `stalled` state. Under WR-Q3 and WR-Q4 every record ends by
confirmation, rejection or release at its end date, so no state is left
for it to describe (rule 15). The log alarm for a reservation past the
900-block horizon is not a reported state and stays an operator signal.

An empty list means nothing is in flight. No field is absent or `null` to
mean that (rule 43). A new required list is additive for a reader that
ignores unknown keys; a reader that refuses unknown keys updates in the
same change.

**Every state comes from sealed records.** `pending` and `dispatched` are
the record's `PendingPostState`. `expired` is the record's durable
`reference_height` (WR-Q3) against the clock below. No state is read
from the in-memory alarm sets (§2), so each one survives a restart.

**The clock is the wallet ledger's synced height**, the one
`get_wallet_info` already reads (`queries.rs:258-259`). The dispatcher
judges against the sweep's claimed daemon count (`pscan/task.rs:435-437`),
which the RPC does not read. Both are reads of one daemon's claimed tip on
two cadences, so they can disagree by about one sweep interval.

**Naming.** `at` is a `ChainCount` (`pending_post_block.rs:119-122`). The
wire converts it to the tip height, `count − 1`, and names it
`dispatched_at_height`, as every other height on this response is a
height (`HEIGHT_SEMANTICS.md`).

**Open strings.** `kind`, `state` and `outcome` (WR-Q2) are open strings
with documented values. The contract already refuses a closed response
enum for `posture`, because an older validator would reject the whole
`staking_info` reply over one display field (`wallet_rpc.yaml:2830-2842`).

**The two existing rule-43 breaches are fixed in the same change.**

- `pscan_synced_height` becomes required, and `null` when the wallet has
  never scanned as a staker. "Never scanned" is an answer, not something
  withheld.
- `recovery_pending_reopen` loses `serde(default)` and is added to
  `wallet_rpc.yaml` as required.

Both tighten existing fields. A Rust reader built from the new type
refuses an older wallet RPC's reply that omits either. The wallet RPC
and its clients ship together pre-genesis, so only mixed builds are
affected.

**Falsifiers.**
- A `staking_info` reply with no `in_flight` key, or `null` in its place,
  fails to decode.
- A test seals a `Dispatched` record with reference height `r`, advances
  the ledger clock past `r + 100`, restarts the engine, and reads
  `expired` with `funds_return_at == r + 100`.
- `rg -n 'stalled' rust/shekyl-wallet-rpc/src rust/shekyl-wallet-contract/src docs/api/wallet_rpc.yaml`
  returns nothing.
- `rg -n 'alarmed_this_session|alarmed_reservations' rust/shekyl-wallet-rpc`
  returns nothing.

### WR-Q2 — How an ending is reported once the record is gone — RULED 2026-10-15

Today removal is the whole effect (`dispatch.rs:799-803`). Dispatch runs
on a background tick, so no RPC call is waiting for the answer.

**Ruled.** The pending block keeps one durable **last outcome** per
`(kind, persona)`, the key every pending record set already uses.
`staking_info` reports them as a second required list, `outcomes`, each
entry with:

- **`kind`**;
- **`outcome`**, one of four:

  | `outcome` | When | `funds` |
  | --- | --- | --- |
  | `rejected` | a terminal verdict removed the record | `returned` |
  | `expired` | the end date passed with every reserved input still live: the transaction never landed | `returned` |
  | `ended_unconfirmed` | the end date passed for a record with **no** reserved inputs, the Q11 zero-fee claim, whose landing the scan cannot see (WR-Q3) | none were held |
  | `spent_elsewhere` | the end date passed with the record's reserved inputs **partly** spent by another transaction (WR-Q3) | the unspent rest is `returned` |

- **`reason`**: a user sentence, never an enum name (rule 81):
  - `rejected`: chosen from `TerminalErrorKind`, starting from the
    sentence already shipped, `STAKING_UNAVAILABLE_ON_THIS_DAEMON`
    (`dispatch.rs:53-56`). Every other kind gets a row before the commit
    lands.
  - `expired`: one sentence that does not blame the user, since under
    §1.1 the cause is usually the wallet's own timing. For example: "The
    stake was not accepted in time and has been withdrawn. Its funds are
    spendable again."
  - `ended_unconfirmed`: "This reward claim could not be confirmed. If it
    was accepted, the reward it earned will appear in your balance."
  - `spent_elsewhere`: "Some of the funds set aside for this were spent by
    another transaction. The rest are spendable again. This should not
    happen; check the wallet's logs and your keys."
- **`at_height`**: the tip height when the outcome was written;
- **`funds`**: `returned`, or `none_held` for `ended_unconfirmed`.

**How it is written.** In the same `mutate` closure that removes the
record (`dispatch.rs:800-802` for a rejection; the end-date release of
WR-Q3 for the other three): one seal, so the two cannot disagree after a
crash. The removal-ordering contract (`pending_post_block.rs:105-112`) is
unaffected: a rejected post never carries a match, and a record released
at its end date cannot gain one (WR-Q3).

**How it is cleared.**
- By the next successful seal of the same kind for the same persona.
- Or by `acknowledge_staking_outcome { kind }`, which acts on the active
  persona as every staking action does (WR-Q5).
- An outcome for a persona that is not active shows in `outcomes` but
  cannot be acknowledged; only that persona's next seal of the same kind
  clears it.

**Schema.** `PENDING_POST_VERSION` 12 → 13, refuse-not-migrate, schema
snapshot (rule 42), shared with WR-Q3's `reference_height`.

**Falsifier.** The armed tripwire
`e2e_the_cxx_daemon_answers_join_market_unsupported`
(`engine/regtest_e2e.rs:3481`) drives a terminal rejection end to end
against the real C++ daemon. Extended: after the rejection,
`staking_info` shows `outcomes[0].outcome == "rejected"` for
`kind == "stake"`, `reason` is the shipped sentence,
`funds == "returned"` and `in_flight` is empty. After a restart it still
does.

### WR-Q3 — How a record that will never land ends — RULED 2026-10-15

**Ruled: release at the end date.**

- A record's **end date** is `reference_height +
  FCMP_REFERENCE_BLOCK_MAX_AGE`, inclusive (§2). Past it, no block on any
  chain can include the transaction.
- Once the staking scan's sealed frontier reaches the end date, the
  record is removed, its reservation with it, and an outcome (WR-Q2) is
  written in the same save. `funds_return_at` is the end date.
- The frontier already trails the tip by `ARCHIVAL_REORG_DEPTH_BLOCKS`
  (720): the sweep ceiling is that far behind (`pscan/start.rs:93-95`), so
  every block at or below it is final under the wallet's own model. The
  release therefore needs no further margin.
- The release runs in the dispatch tick, which already holds the scan's
  accrual (`pscan/task.rs:426-437`). It runs last in the tick's one
  `mutate` pass (`dispatch.rs:539`), after both retires.
- **Fee:** none. **User action:** none.

**The reference height is durable.** Each pending record gains
`reference_height: BlockHeight`, written at assembly, where the height is
already in hand (`reference.height`; `release_dispatch.rs:506`). Schema
v13, refuse old files (rule 42), shared with WR-Q2. The transaction
itself carries only a block hash (`rv.referenceBlock`,
`blockchain.cpp:3600-3601`), and resolving that hash every tick through
the wallet's own chain view could fail to answer.

**Nothing is sent past the end date.** The driver makes no first send of
a post due after its end date (under §1.1, most are) and no resend after
it. Such a send can never land, wastes traffic, and shows one origin
re-offering the same dead bytes on every tick. With the end date always
first, the 900-block alarm horizon no longer governs bond posts, and its
bond-post use retires (rule 15).

**How each record ends at the end date.** Both retires and the release
read the same evidence: one accrual, one frontier, one reorg depth
(`pscan/task.rs:426-437`). At release the frontier is at or past the end
date, and a record's transaction can only have landed at or below it.

| What the scan shows | Kind | What happens | Outcome |
| --- | --- | --- | --- |
| a reorg-deep JoinMarket match for the persona | stake | `remove_confirmed` already retired it (`dispatch.rs:549`) | none: a confirmed stake |
| every reserved input gone from live funding | claim, drain, exit | `remove_settled` already retired it (`dispatch.rs:561`; `pending_post_block.rs:1003-1043`) | none: it landed |
| no match, or every reserved input still live | any | released; the reservation is freed | `expired` |
| the record reserves **no** inputs | the Q11 zero-fee claim | released; the per-persona claim gate reopens | `ended_unconfirmed` |
| reserved inputs **partly** spent | claim, drain, exit | released; the unspent rest is freed; a loud alarm | `spent_elsewhere` |

**The phantom-slot cleanup is safe after a release.** The cleanup
(`engine/stake_persist.rs:187-231`) drops a bonded slot when covered scan
evidence shows no bond and no pending record bridges it.

- No block above the end date can include the post: both daemons refuse a
  reference older than `MAX_AGE` (§1.1).
- Every block at or below the end date is inside the sealed frontier,
  which is reorg-deep, and was scanned with the persona watched while the
  pending record kept it live.
- So if the post landed, the scan holds its match and the confirmation
  retire ran first. If it did not, no bond exists and none can. A slot
  the cleanup then drops is a stake that never happened.

**The Q11 zero-fee claim.**

- **It carries a reference, so it has an end date.** It has no fee
  inputs, but its backing's membership path is assembled against one
  reference snapshot with the rest of the claim (`claim_orchestrator.rs:39-42`,
  step 5).
- **Why it is released.** Past its end date the claim can never be mined,
  so holding it protects nothing. `remove_settled` never settles an empty
  reservation (`pending_post_block.rs:987-1001`), so today the persona's
  claim gate (`has_live_claim_for`) stays shut for good, and that persona
  can never claim again.
- **Why the outcome is `ended_unconfirmed`, not `expired`.** The scan
  cannot tell whether this claim landed. If it did, the reward arrives
  through the scan like any other.
- **After the gate reopens.** The next claim is built from the daemon's
  claim source (`fetch_vouched_claim_source`, `emission_source.rs:752`).
  Since the release waits for a reorg-deep frontier, that source already
  reflects the old claim if it landed.

**The partly spent reservation.**

- **What it means.** A record's own transaction spends all of its inputs
  or none. A part spent means another transaction spent some, and nothing
  outside the wallet can spend `P`'s outputs at all
  (`pending_post_block.rs:979-980`). So it signals a wallet bug or a
  compromised key.
- **Why it is released.** Past the end date the record's transaction can
  never be mined, so the unspent rest is freed.
- **The alarm.** It is loud, and it survives a restart.
  - The durable `spent_elsewhere` outcome is the system of record.
  - A new operator-alarm condition with the `LatchedRederived` lifetime
    (`shekyl-operator-alarm/src/lib.rs:259-282`) is re-detected from that
    outcome on every wallet start, and clears when the outcome is
    acknowledged.
  - An error log line is written on each start while the outcome stands.
  - Nothing reads the alarm board in production yet (FOLLOWUPS, "No
    production reader of any operator alarm board"). Until that changes,
    the log line and the `staking_info` outcome are what a person sees.

**Invariant: the end date assumes the age limit never rises.** The end
date is `reference_height + FCMP_REFERENCE_BLOCK_MAX_AGE` read now, while
a record was signed under the limit in force then.

- A **raised** limit would make the computed end date too early. The
  wallet would release, and let the phantom-slot cleanup drop, a bond
  that can still land: the stuck-funds case the cleanup exists to
  prevent.
- A **lowered** limit only holds funds longer.
- The limit is a consensus constant (`config/consensus_constants.json:5`);
  raising it makes a different chain. The sentinels that pin it today sit
  in other modules (`reference.rs:69`, `tx_against.rs:71`).
- **Ruled:** the release module carries its own compile-time sentinel,
  `FCMP_REFERENCE_BLOCK_MAX_AGE == 100`, whose message names this round
  and says what raising the limit breaks, and a test beside it.
- **Reopen** (rule 21) if a per-era limit is ever proposed: then each
  record stores the limit in force at signing beside `reference_height`.

**Wargames.**

| Case | Outcome |
| --- | --- |
| The post lands late | It can land only at or below its end date. The scan matches it before the frontier passes the end date, and the confirmation retire removes it as a confirmed stake. No release fires |
| A reorg near the end date | The release waits for a frontier that is itself reorg-deep. A reorg within that depth changes nothing; one deeper is outside the wallet's finality model everywhere |
| A hostile node holds the bytes and broadcasts them later | After the end date, every daemon refuses them for their reference age. Before it, they can land only as the user's own stake, which the scan retires as confirmed |
| The scan stalls | The frontier does not advance and nothing is released early. The state stays `expired` with its `funds_return_at` |
| The consensus age limit changes | Covered by the invariant above: the release module's sentinel fails the build |

**Rejected alternatives.**

- **Free the inputs at the 900-block horizon — REJECTED.**
  - It is never final: the horizon bounds waiting, not landing
    (`dispatch.rs:185-216`).
  - The user's next send becomes the transaction that loses a race.
  - It removes the pending record while a bond can still land. That
    record is the bridge that stops the phantom-slot cleanup from
    dropping a real bond, and a dropped slot can never be re-adopted
    (`stake_persist.rs:211-214`).
- **Cancel by spending the reserved inputs, through a `Cancelling` state
  arm — REJECTED.**
  - It costs a fee.
  - It is an on-chain linkage event: the cancel spends inputs whose key
    images the post already published.
  - It is unneeded: the reference window ends every record by itself,
    for free and with the same finality.

**Falsifiers.**
- A sealed post with reference height `r` and a frontier below `r + 100`
  stays in `in_flight` as `expired`. A frontier at `r + 100` removes it,
  writes `outcomes[0].outcome == "expired"` in the same seal, and
  releases its gindexes.
- A post matched by the scan at or below `r + 100` is retired as
  confirmed, and no outcome is written.
- A drain whose inputs are all absent from live funding at that frontier
  is retired as settled, with no outcome.
- A drain with part of its inputs absent is released at the frontier
  `r + 100`. Its remaining gindexes are freed, `outcomes[0].outcome ==
  "spent_elsewhere"` is written in the same seal, and the alarm condition
  is raised. After a restart the alarm is raised again from the outcome,
  and acknowledging the outcome clears it.
- A zero-fee claim with no reserved inputs is released at the frontier
  `r + 100`, `outcomes[0].outcome == "ended_unconfirmed"` is written, and
  `has_live_claim_for` for its persona returns `false`.
- A due tick past `r + 100` sends nothing.
- Changing `fcmp_reference_block_max_age` fails the release module's own
  sentinel.

### WR-Q4 — One surface for claims, drains and exits — RULED 2026-10-15

The kinds fail differently today (§2): a rejected stake is removed, an
exit rejected on its one send is removed at the seam, and a rejected
claim or drain is **held**, because the prune that would remove it is
leg 4's empty body.

**Each kind carries a reference, and none re-proves.**

| Kind | Carries an FCMP++ reference | On `StaleRoot` |
| --- | --- | --- |
| Claim | yes, through its backing membership path (`claim_orchestrator.rs:25-30`, `:39-42`) | the seam returns the error; the record is held; never resent or re-proved (`claim_dispatch.rs:422-435`) |
| Drain | yes (`drain_dispatch.rs:20-24`) | as the claim |
| Exit | yes (`release_dispatch.rs:503-506`) | held; never resent or re-proved (`:728-736`) |

**Ruled: release at the end date, for every kind, in this round.** WR-Q3's
release applies to all four kinds and to every case in its table,
including the empty and the partly spent reservation.

- **Why it lands alone.** It is the prune half of leg 4, by proof, and
  adds no resubmit, so it keeps the FOLLOWUPS row's "never land resubmit
  alone". That row's security note names the reference age window as the
  other bound on the replay channel. Past the end date the retained copy
  cannot be mined by anyone, so pruning it then loses nothing.
- **What leg 4 keeps.** Byte-identical resubmit within the lifetime, and
  an earlier prune on a definite terminal verdict.
- **What it costs.** The `reference_height` field on all four kinds (the
  one shared v13 bump). A rejected claim, drain or exit holds its funds
  until about a day after its end date, and then reports `expired`, not
  `rejected`.

**The exit's "fate unknown" gets an end.** `unstake`'s
`-29522 UNSTAKE_FATE_UNKNOWN` today has no way to resolve. Its message
says the record is held "until it settles" and not to retry blindly
(`shekyl-wallet-contract/src/error.rs:945-949`), and the contract says it
waits for "the recovery slice (FOLLOWUPS dispatch-driver
prune+resubmit)" (`wallet_rpc.yaml:1344-1353`). Under this ruling,
`outcomes` holds a definite answer for the exit by `funds_return_at`:
settled, `expired`, or `spent_elsewhere`. The error's text and its
contract entry say so in plain words. For example: "Check
`staking_info`: by the height it names, this exit will either have
completed or been withdrawn with its funds returned."

**Falsifiers.**
- A sealed, dispatched drain with reference height `r` reads
  `kind == "drain"`, `state == "expired"` once the clock passes `r + 100`.
  It leaves `in_flight` with an `outcomes` entry once the frontier
  reaches `r + 100`.
- `rg -n 'reference_height' rust/shekyl-engine-state/src/pending_post_block.rs`
  hits on `PendingBondPost`, `PendingEmissionClaim`, `PendingDrain` and
  `PendingRelease`.
- The `-29522` message names `staking_info`.

### WR-Q5 — What the response reveals, and to whom — RULED 2026-10-15

**To whom: the wallet's owner.** The wallet RPC has no per-connection
grant table. A caller reaches it on a Unix socket protected by
filesystem permission, or on TCP behind HTTP basic auth or a loopback
bind (`shekyl-wallet-rpc/src/auth.rs:6-10`).

- Every admitted caller holds every method, the same set that can already
  call `transfer` and `unstake`.
- The grants of `RPC_CHANNEL.md` §6.1 are the daemon's. The slice that
  puts the wallet RPC on the channel, RT-W12, is not authorized
  (`RPC_CHANNEL.md:1978`).
- If L1 ever gains per-connection grants, these fields belong to whatever
  grant then holds staking state.

**What the lists reveal.**

- **Counts.** The length of `in_flight` is the number of records in
  flight per kind. The code treats that count as `P`-activity volume and
  redacts it from `Debug` (`pending_post_block.rs:133-136`, `:390-392`,
  `:444`). For stakes it is already derivable from `staking_info`:
  `bonded_principal_pending` is that count times the bond floor
  (`staking_read.rs:236-251`).
- **Timing.**
  - `dispatched_at_height` reveals when the wallet first sent a record.
  - `funds_return_at` reveals the reference height, so roughly when the
    record was built. For a sent record, every node that saw the bytes
    already knows that. For a stake that expired before it was sent
    (§1.1), it tells the owner when the wallet signed. It is not
    coarsened.
  - The wire never carries `anchor_t0`, the offset or the due count, and a
    `pending` entry reveals nothing about when it will be sent.
- **No persona.** Persona ids, transaction bytes and funding gindexes
  never reach the wire.

**No slots, no handles.** Every staking action refuses a `p_slot`
parameter (`handlers.rs:393-403`), and `stake` says "the user never names
a slot" (`lifecycle.rs:836-838`, rule 81). So entries carry neither a
slot nor a handle, and `acknowledge_staking_outcome` acts on the active
persona. **Reopen** (rule 21) if a wallet must act on a record of a
persona that is not active, including acknowledging that persona's
outcome: the shape then is an opaque handle, random and persisted at
seal time, never derived from the persona or the bytes.

**Linkage, said to the user.** A broadcast record publishes the key
images of its inputs to every node that saw it in a pool. When its funds
come back, any later spend of them can be linked to the attempt. The
`expired`, `rejected` and `spent_elsewhere` outcomes of a record that was
sent carry, in plain words: "Anyone who saw this attempt can link a later
spend of these funds to it."

**Logs.** Nothing new is logged, except the `spent_elsewhere` error line
on each start (WR-Q3), which names no persona.

**Falsifiers.**
- `rg -n 'p_slot|persona|anchor_t0|offset|gindex'` over the `in_flight`
  and `outcomes` wire types returns nothing.
- A decode test refuses an `acknowledge_staking_outcome` request carrying
  `p_slot`.

---

## 4. Proving it

The ruled shape is proved against a real daemon (regtest), not mocks,
where a daemon can produce the case.

- **Now:** the terminal rejection, end to end. The #1075 tripwire already
  drives it against the C++ daemon (WR-Q2's falsifier).
- **At `DEL-008`:** a dispatched stake, a late landing and an end-date
  release all need a daemon that admits a kind-5 JoinMarket post. That is
  the Rust daemon at the cutover. The named blocker is the FOLLOWUPS row
  "The five bonded regtest walks are decided dark…", and the fixtures for
  those rows land with the walks it un-darkens. Until the bond lane's
  Round 0 on §1.1 lands, an `expired` outcome is what most stakes on that
  daemon will show.
- **Without a daemon:** the state projection (WR-Q1), the outcome write
  (WR-Q2) and every row of WR-Q3's release table are tested against
  sealed state with a fixed clock and frontier. They are projections of
  durable state and need no network to be right.

## 5. Follow-on: settlement evidence for the Q11 zero-fee claim — not ruled here

WR-Q3 releases the zero-fee claim as `ended_unconfirmed` because the scan
cannot see whether it landed. The real fix closes the FOLLOWUPS row "Q11
zero-fee-input emission claim has no settlement evidence", whose named
blocker is that the accrual has no claim-match set.

**Is the minted output's arrival that evidence? Not on its own, today.**

- The scan does recognise the claim's own transaction. A recovered output
  in a transaction carrying the owning persona's own emission input is
  classed `EmissionReward` (`pscan/scan_step.rs:835-838`; `:255-263`).
- But the funding record keeps no transaction hash
  (`shekyl-engine-state/src/pscan_state.rs:214-260`). So a later
  `EmissionReward` output cannot be tied to a particular claim, and the
  persona's earlier claims mint the same lineage.
- **The evidence exists at one point:** the classification step has the
  transaction hash in hand (`wo.transaction()`, `scan_step.rs:835`).
  Recording `(persona, transaction hash)` there, for each emission
  transaction of ours that the scan sees, is the claim-match set. A
  pending claim whose stored bytes hash to an entry has landed. That
  closes the Q11 row, and the zero-fee claim then retires as landed,
  before its end date, like any other.
- This depends on the claim minting an output the persona's scan
  recovers. A claim that paid nothing to `P` would leave no recovered
  output to classify, and would need the emission input itself recorded.

The follow-on is the claim lane's. Until it lands, `ended_unconfirmed` is
the honest outcome for that one case.

## 6. What this round does not do

- No C++.
- No wallet-contract removal. `JoinMarketUnsupported` stays enumerated
  until `DEL-008` deletes it (the FOLLOWUPS row "The five bonded regtest
  walks are decided dark…").
- No change to when or how a bond post is signed. That belongs to the
  bond lane's Round 0 (§1.1).
- No byte-identical resubmit for claims, drains or exits. That stays
  leg 4's.
- No claim-match set (§5).
- **No code in this PR.** The rulings are implemented in a separately
  authorized slice, with the falsifiers above as its acceptance tests.
