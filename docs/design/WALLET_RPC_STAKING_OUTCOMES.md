# Wallet RPC — staking outcomes a user can see: Round 0

**Status:** OPEN — Round 0, questions **POSED 2026-10-15**; nothing is
ruled. Each question carries a default, its reason, what the alternative
changes, and a falsifier. **No code until the questions are ruled.**

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

| Kind | Record | Sent by | Terminal rejection | Ambiguous or retryable | Past the horizon |
| --- | --- | --- | --- | --- | --- |
| Stake (bond post) | `PendingBondPost` (`:138-177`) | the dispatch driver, every sweep tick (`pscan/dispatch.rs:521-842`) | record removed, reservation released, one log line (`dispatch.rs:794-819`) | resubmitted byte-identical on the next due tick (`:820-839`) | resubmits stop; one log alarm per session (`:601-610`, `:719-735`); record and reservation held |
| Emission claim | `PendingEmissionClaim` (`:209-224`) | the claim seam, once (`claim_dispatch.rs:422-435`) | **held**: any submit failure leaves the record live | held | one log alarm per session (`dispatch.rs:566-599`, `:696-717`); held |
| Drain | `PendingDrain` (`:252-266`) | the drain seam, once (`drain_dispatch.rs`) | **held** | held | as the claim |
| Exit (`Release`) | `PendingRelease` (`:296-309`) | the release seam, once (`release_dispatch.rs:655-669`) | **removed at the seam** on a definite first-send `RejectedTerminal` (`:304-310`, `:633-669`; #601) | held; the user already sees `-29522 UNSTAKE_FATE_UNKNOWN` from `unstake` (`shekyl-wallet-contract/src/error.rs:339`) | as the claim |

**The horizon.** `DISPATCH_ALARM_HORIZON_BLOCKS` is 900: the reorg-deep
confirmation floor (720) plus 25 % (`dispatch.rs:185-216`). It bounds how
long the driver waits for a confirmation before it alarms. It says
nothing about whether the transaction can still land (WR-Q3).

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
- owed in `docs/FOLLOWUPS.md:420`, which marks the prune a security item
  that must land together with byte-identical resubmit.

### 2.1 Corrections to the brief, found at source

- **The cause type.** There is no wallet-contract `RejectCause`.
  `RejectCause` is the daemon reply's type
  (`shekyl-rpc-types/src/lib.rs:205`). The cause the dispatcher holds is
  the engine's `TerminalErrorKind` (`engine/error/submit.rs:34`).
- **Exits are not held forever on a terminal rejection.** The exit seam
  prunes on a definite first-send refusal. Claims and drains are held.
- **The pool's three-day clock is per node, from that node's admission.**
  `CRYPTONOTE_MEMPOOL_TX_LIVETIME` is three days
  (`src/cryptonote_config.h:104`), about 2,160 blocks at 120 s. Age is
  measured from `receive_time` (`src/cryptonote_core/tx_pool.cpp:1080`).
  A byte-identical resend to a node that still holds the transaction does
  not reset it. Only re-admission after eviction, or a relay-method
  upgrade, does (`tx_pool.cpp:498-512`). Every re-admission anywhere
  starts a new clock, so there is no network-wide bound.
- **The dispatcher's clock is not one the RPC has.** The driver judges
  against the sweep's claimed daemon count (`pscan/task.rs:435-437`).
  `staking_info` reads only sealed files (`engine/staking_read.rs:417-450`).
- **The redaction citation.** The block treats the count of in-flight
  posts as `P`-activity volume at `pending_post_block.rs:133-136`,
  `:390-392` and `:444`.
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
  - `stalled`, with `dispatched_at_height`: past the horizon, funds still
    held.
- **No per-record handle.** See WR-Q5.

An empty list means nothing is in flight. No field is absent or `null` to
mean that (rule 43). A new required list is still additive for a reader
that ignores unknown keys; a reader that refuses unknown keys must update
in the same change.

**Every arm comes from sealed state.** `pending` and `dispatched` are the
record's `PendingPostState`. `stalled` is computed: `Dispatched { at }`
with `clock ≥ at + DISPATCH_ALARM_HORIZON_BLOCKS`. It is never read from
the in-memory alarm sets (§2). It therefore survives a restart, which the
log alarm does not.

**Sub-question (a), the clock.** The dispatcher's clock is the sweep's
claimed count, which the RPC does not read.

| Candidate | Disagrees with the log alarm by | Cost |
| --- | --- | --- |
| **The wallet ledger's synced height**, the one `get_wallet_info` reports (`queries.rs:258-259`) — **default** | the gap between two reads of one daemon's claimed tip on two cadences: about one sweep interval | none; already read under the same guard in `get_wallet_info` |
| The sealed P-scan frontier (`pscan_synced_height`) | the reorg depth: the frontier trails the tip by 720 blocks (`config/consensus_constants.json:26`) | none, but `stalled` would appear 720 blocks late |
| A persisted last-tick count in the pending block | none | a schema bump, and a seal on every tick |
| A daemon read inside `staking_info` | none at read time | a network call in a read-only method that today makes none |

**Sub-question (b), naming.** `at` is a `ChainCount`
(`pending_post_block.rs:119-122`). A wire field named `…_height` that
carries a count is the bug class `HEIGHT_SEMANTICS.md` exists to stop.

- Default: convert to the tip height, `count − 1`, and name it
  `dispatched_at_height`. Every other height on this response is a
  height.
- Alternative: carry the count and name it `dispatched_at_count`.

**Sub-question (c), closed or open strings.** The contract already
rejects a closed response enum for `posture`, because an older validator
would refuse the whole `staking_info` reply over one display field
(`wallet_rpc.yaml:2830-2842`).

- Default: `kind` and `state` are open strings with documented values,
  for the same reason.
- Alternative: closed enums. A new kind, such as a cancel (WR-Q3), would
  then break every older client's balance reading.

**Sub-question (d), the existing rule-43 breaches.** Default: fix both in
the same change, because they sit in the same response type.

- `pscan_synced_height` becomes required and `null` when the wallet has
  never scanned as a staker. "Never scanned" is an answer, not something
  withheld.
- `recovery_pending_reopen` loses `serde(default)` and is added to
  `wallet_rpc.yaml` as required.

The alternative is to name them in FOLLOWUPS against `WI-RPC` and leave
them.

**What the alternative changes.** A per-slot field that is absent when
idle is the shape rule 43 forbids. It also puts slot ordinals on
`staking_info`, which WR-Q5 argues against.

**Falsifier.**
- A `staking_info` reply with no `in_flight` key, or with `null` in its
  place, must fail to decode.
- A test seals a `Dispatched` record, advances the ledger clock past
  `at + 900`, restarts the engine, and reads `stalled`.
- `rg -n 'alarmed_this_session|alarmed_reservations' rust/shekyl-wallet-rpc`
  must return nothing.

### WR-Q2 — How is a terminal rejection reported, when the record is gone?

Today removal is the whole effect (`dispatch.rs:799-803`). Nothing durable
remains to report, and dispatch runs on a background tick, so no RPC call
is waiting for the answer.

**Default.** The pending block gains one durable **last outcome** per
kind, scoped as WR-Q4 rules. `staking_info` reports these as a second
list, `outcomes`, each entry with:

- **`kind`**;
- **`outcome`: `rejected`** — the only value this round defines;
- **`reason`**: a user sentence chosen from `TerminalErrorKind`, never
  the enum name (rule 81). The table starts from the sentence already
  shipped for one cause, `STAKING_UNAVAILABLE_ON_THIS_DAEMON`
  (`dispatch.rs:53-56`). Every other kind gets a row before the commit
  lands;
- **`at_height`**: the tip height when the rejection was observed;
- **`funds`: `released`** — true by construction, since removal is the
  release.

**How it is written.** The outcome is written in the same `mutate`
closure that removes the record (`dispatch.rs:800-802`): one seal, so the
two cannot disagree after a crash. The removal-ordering contract
(`pending_post_block.rs:105-112`) is unaffected. A terminal rejection
never carries a match, so the phantom-GC bridge it protects never applies
to a rejected post.

**How it is cleared.**
- Cleared by the next successful seal of the same kind for the same
  persona.
- Or cleared by an explicit `acknowledge_staking_outcome { kind }`, which
  acts on the active persona as every staking action does (WR-Q5).

**Cost.** A persisted change: `PENDING_POST_VERSION` 12 → 13,
refuse-not-migrate, schema snapshot (rule 42). A v12 file is refused and
re-assembled, as every earlier bump was.

**Alternative.** Report the outcome only in the response of the call that
triggered it. This fails for the stake: dispatch is a background tick and
no call is waiting. It works for the exit, which already does it (`-29522`
and the seam's synchronous refusal).

**Falsifier.** The armed tripwire
`e2e_the_cxx_daemon_answers_join_market_unsupported`
(`engine/regtest_e2e.rs:3481`) already drives a terminal rejection end to
end against the real C++ daemon. Extend it: after the rejection,
`staking_info` shows `outcomes[0].kind == "stake"`, `reason` is the
shipped sentence, `funds == "released"` and `in_flight` is empty. After a
restart it still does.

### WR-Q3 — Can a user end a stalled stake, and on what terms?

**Why freeing the inputs is never final.**

1. **The horizon bounds waiting, not landing.** The 900 blocks are a
   confirmation-delay bound derived from the reorg depth
   (`dispatch.rs:185-216`).
2. **The pool forgets slowly and unevenly.** Each node keeps the
   transaction three days from its own admission, and re-admission
   anywhere restarts that clock (§2.1).
3. **The signed bytes stay valid until one of their inputs is spent.**
   Any node that saw them can broadcast them later. A hostile node can
   hold them on purpose.
4. **Freeing the record can lose a real bond.** The pending record is the
   bridge that stops the open-time phantom GC from dropping a bond the
   scan has not yet matched (`engine/stake_persist.rs:187-231`). Remove
   it while the bond can still land, and a later open can see "no record,
   covered absence" and drop the slot. The cursor is then burned, and the
   slot can never be re-adopted (`:211-214`). The bond would sit on chain
   with no wallet slot to serve or exit it.

**Option (a) — free the inputs.** The record is removed after the
horizon, and coin selection may use the inputs again.

- **Fee:** none.
- **Finality:** never.
- **What it really does:** makes the user's next send the transaction
  that loses a race, and exposes a late bond to the phantom GC (point 4).

**Option (b) — cancel by spending.** The wallet spends the post's
reserved inputs in a transaction of its own. The stake ends only when
that spend is reorg-deep (`ARCHIVAL_REORG_DEPTH_BLOCKS`, 720). From then
on, the bond can never land.

- **Fee:** one transaction.
- **Finality:** 720 blocks after the cancel confirms.
- **Shape:** the stake record is **not** removed when the cancel is
  sealed. It moves to a new state arm, `Cancelling`, which carries the
  cancel's bytes.
  - The reservation and the phantom-GC bridge both stay in place.
  - No second record reserves the same inputs; the seal classifier would
    refuse one as `InputRaced` (`pending_post_block.rs:341-366`).
  - The record is removed only when the cancel's inputs are seen spent,
    reorg-deep.
  - This is a schema change (v13, with WR-Q2's).
- **Destination:**
  - **Default:** the principal address, through the existing drain
    builder. The destination is the wallet's own principal address and
    never caller-supplied (`drain_dispatch.rs:28-31`). The drain is
    already byte-identical to a principal transfer (FOLLOWUPS row "The
    five bonded regtest walks…"). Funds return to the spendable balance,
    which is what a user who cancels expects.
  - **Alternative:** a `P`→`P` self-spend that keeps the funds staking
    side, for a user who means to stake again. No such builder exists
    today; it would be new, with its own decorrelation question.
  - Either destination spends inputs whose key images the bond post
    already published (WR-Q5).

**Default: (b), offered only from `stalled`.**
- A verb `cancel_stake`, acting on the active persona like every other
  staking action; no slot parameter (WR-Q5).
- The response says, in plain words:
  - that the stake ends when the cancel is final, about a day after it
    confirms;
  - that it costs one fee;
  - that the cancel can be seen to come from the same funds (WR-Q5).
- (a) is rejected: it cannot be made final, and point 4 makes it unsafe
  as well as weak.

**Wargames.**

| Case | Under (a) | Under (b) |
| --- | --- | --- |
| The bond lands after the user acts | The user's next send loses the race and is `TerminalRejected` in the transfer journal. The bond lands with no pending record; an open before the scan matches it can drop the slot for good (point 4) | If the bond lands before the cancel, the scan matches it and the record retires as a confirmed stake; the cancel is a double spend and dies with the record. The user is staked, consistently |
| The cancel is reorged out, shallower than 720 | — | The record stays `Cancelling` with its reservation. Either transaction may land on the new chain: the bond ends as a confirmed stake, or the cancel as a cancelled one. Nothing is freed early |
| A hostile node holds the bond and broadcasts it after the user acts | The bond lands whenever the node chooses; same as row one | Before the cancel is final: as row one. After it: the bytes spend a spent input and can never be mined |

**Falsifier.**
- A test removes the record of a post whose bond later lands (option
  (a)), opens the wallet before the scan's match, and observes the slot
  dropped. This proves point 4 at source before the ruling.
- For (b): `rg -n 'Cancelling' rust/shekyl-engine-state/src/pending_post_block.rs`
  hits, and a regtest fixture confirms a cancel, buries it 720 deep, and
  then reads `in_flight` empty and the bytes of the bond refused by the
  daemon as a double spend.

**Blocked fixture.** No bond post can land on the C++ daemon: it answers
every kind-5 JoinMarket post `JoinMarketUnsupported`, and the five bonded
regtest walks are decided dark until `DEL-008` (FOLLOWUPS:93). The
late-landing rows of the wargame cannot run against a real daemon until
then. The rejection path can, and it is WR-Q2's falsifier.

### WR-Q4 — Does one surface cover claims, drains and exits?

The kinds do not fail the same way (§2).

- **A stake** rejected terminally is removed.
- **An exit** rejected on its one send is removed at the seam.
- **A claim or a drain** rejected terminally is **held**. It looks exactly
  like a stall, because the prune that would remove it is leg 4's empty
  body.

So a `rejected` outcome for a claim or a drain cannot exist until leg 4
lands.

**Option (a) — this round takes on leg 4.** Every kind gets the same
`rejected` outcome, written in the same seal as the removal.
- **Cost:** FOLLOWUPS:420 requires the prune to land **together with**
  byte-identical resubmit, because the retained copy of a rejected claim
  or exit is a replay channel. So (a) is both halves, not the prune
  alone.
- It also needs the claim and drain seams to keep the verdict, which they
  return to the caller and do not persist today.

**Option (b) — report what the state allows.**
- Claims, drains and exits appear in `in_flight` as `pending`,
  `dispatched` or `stalled`.
- Stakes, plus exits rejected at the seam, appear in `outcomes`.
- A claim or drain that was rejected shows as `stalled` once past the
  horizon. The response says what that may mean: "this may have been
  refused; your funds are held until the wallet can tell".
- `outcomes` gains those kinds when leg 4 lands, with no further wire
  change.
- **Cost:** a rejected claim or drain shows as stalled for up to 900
  blocks, about 30 h, and then stays stalled.

**Default: (b).** It keeps this round to the read surface and the stake.
It also does not open a security item from a UX round. One list, keyed by
kind, carries every kind; what each kind can say is set by what its state
records, and the response says so.

**Falsifier.**
- Under (b): a sealed, dispatched drain past the horizon reads
  `kind == "drain"`, `state == "stalled"`, and no `outcomes` entry for
  it.
- When leg 4 lands, the same fixture after a terminal rejection must
  read an `outcomes` entry. Leg 4's own commit carries that test.

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
- **Timing.** `dispatched_at_height` reveals when the wallet first sent
  the record. A `pending` entry must reveal nothing about when it will
  be sent. Default: the wire never carries `anchor_t0`, the offset, or
  the due count, because those are the decorrelation plan.
- **No persona.** Persona ids, transaction bytes and funding gindexes
  never reach the wire.

**No slots, no handles.**

- Slot ordinals are already on the wire through `get_staked_outputs`
  (`types.rs:770`). But every staking action refuses a `p_slot`
  parameter (`handlers.rs:393-403`), and `stake` says "the user never
  names a slot" (`lifecycle.rs:836-838`, rule 81).
- Default: no slot and no handle on these entries. `cancel_stake` and
  `acknowledge_staking_outcome` act on the active persona.
- Alternative: an opaque handle, random and persisted in the record at
  seal time, never derived from the persona or the bytes. It costs a
  schema field. It is needed only if a wallet must act on a record of a
  persona that is not active.

**Linkage, said to the user.** A broadcast post publishes the key images
of its inputs to every node that saw it in a pool. Any later spend of
those inputs links back to the stake attempt: a cancel, a drain, or an
ordinary send after option (a). This is true whatever this round decides.

- Default: `cancel_stake`'s response says, in plain words, "Anyone who
  saw this stake can tell that the cancel spends the same funds."
- The same sentence goes on any later release path.

**Logs.** Nothing new is logged. Each stall already has its log alarm
(§2).

**Falsifier.**
- `rg -n 'p_slot|persona|anchor_t0|offset|gindex' ` over the
  `in_flight` and `outcomes` wire types returns nothing.
- A decode test refuses a `cancel_stake` request carrying `p_slot`.

---

## 4. Proving it

The ruled shape is proved against a real daemon (regtest), not mocks.

- **Now:** the terminal rejection, end to end. The #1075 tripwire already
  drives it against the C++ daemon (WR-Q2's falsifier).
- **At `DEL-008`:** a dispatched stake, a stall, a late landing and a
  cancel all need a daemon that admits a kind-5 JoinMarket. That is the
  Rust daemon at the cutover. The named blocker is FOLLOWUPS:93, and the
  fixtures for those rows land with the walks it un-darkens.
- **Without a daemon:** the stall projection (WR-Q1) and the outcome
  write (WR-Q2) are tested against sealed state with a fixed clock. They
  are projections of durable state and need no network to be right.

## 5. What this round does not do

- No C++.
- No wallet-contract removal. `JoinMarketUnsupported` stays enumerated
  until `DEL-008` deletes it (FOLLOWUPS:93).
- No change to the dispatcher's alarm horizon, resubmit policy or alarm
  wording.
- No leg-4 body, unless WR-Q4 rules (a).
