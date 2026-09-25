# Reference shapes — S-POOL and the Dandelion++ boundary

**Status:** LIVING CONTRACT — last verified 2026-09-24 at `dev` @ `a1159f1a2`
(maintainer's write-up from the Dandelion++ / P2P rounds, grounded at source
by the S-POOL lane on PR #849). Five items, each with the correct shape, the
ruling or bug it comes from, and what *drifted back to Monero* looks like for
that item, so it can be recognised rather than argued about. Three of the
five lived only in chat and code comments until this file: §92's three-clause
unbundling is in [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) but its
pool-side consequence was recorded nowhere; the `LockedTXN` bug is in the
CHANGELOG and the atomicity audit but was not cited by the store's
discardable-file ruling; the peerlist → Dandelion++ chain was stated wrong in
a review. That is the documented gap this file closes — the port reads the
C++ and the design doc, and the ruling that stops the drift was in neither.
**Consumers:** [`DRS_E1_SPOOL.md`](DRS_E1_SPOOL.md) (SPL-14, SPL-16, SPL-17,
SPL-18, `SPL-Q9`), the E5 pool increment, the P2P-3 slices. Where a section
says *docs owed*, the owing document is named. Every cite is at source on the
verifying tree; a claim this lane could not verify is marked as such rather
than carried.

---

## 1. `LockedTXN` — keep the batched write, refuse the abort-on-drop

**The bug it comes from.** `tx_pool.cpp::get_relayable_transactions` took a
`LockedTXN`, called `update_txpool_tx()` to write Dandelion++ stem/forward
relay timestamps, and returned **without** `lock.commit()`. `LockedTXN`'s
destructor aborts on uncommitted exit, so every relay-timestamp update was
silently rolled back on every invocation — Dandelion++ timing state was never
durable. Classified as a privacy regression (origin-disclosure class), not a
consensus or fund-safety bug ([`CHANGELOG.md`](../CHANGELOG.md), the
"Dandelion++ relay timestamp rollback" entry; the fix is the `lock.commit()`
at `src/cryptonote_core/tx_pool.cpp:1232`, re-verified intact by
[`LMDB_WRITE_ATOMICITY_AUDIT.md`](../LMDB_WRITE_ATOMICITY_AUDIT.md), the
`get_relayable_transactions` row).

**The correct shape.** Two properties, explicitly separated:

- *Keep the property, not the mechanism:* a batched write — a `take_tx` that
  moves a transaction from pool to chain must not half-happen within one
  file. (Across the two files S-POOL creates, that atomicity is **lost and
  accepted**; `DRS_E1_SPOOL.md` SPL-7, `SPL-Q5`: chain commits first, pool
  reconciles at open.)
- *Refuse:* a guard whose `Drop` discards work silently. A Rust batch that
  rolls back on drop, held by a caller who can return early, reproduces the
  defect in a new language.

**As landed in this tree.** The chain store already has the shape that makes
*forgetting to commit unrepresentable*: `ChainStore::write(|batch| …)`
(`rust/shekyl-chain-store/src/store/mod.rs:445–470`) constructs the batch,
runs the closure, and `complete(outcome)` commits on `Ok` and aborts on `Err`;
the caller never holds the batch across a return. The pool file takes the same
shape (`DRS_E1_SPOOL.md` §3.2, SPL-16). Where a handle *must* be caller-held,
the acceptable form is `fn commit(self) -> Result<…>` with `#[must_use]`, so
forgetting is a compile-time warning; and any drop-without-commit path is
**loud** — a log line at minimum, a panic in debug — never a silent abort.

**Drift looks like.** A `PoolBatch` with a `Drop` impl that aborts, described in
a comment as "matching `LockedTXN`'s semantics." That sentence is the tell: it
preserves both halves, and the second half is the bug. (`DRS_E1_SPOOL.md`
§3.2's first draft was this sentence without the comment; corrected
2026-09-24.)

**Docs owed — discharged 2026-09-24:** `DAEMON_REDB_STORE.md` §5.1's
discardable-file row cites the bug and this section.

---

## 2. Relay state ownership — the pool stores evidence, not policy

**What is already true.** `shekyl-relay-privacy` and `shekyl-relay` own the
stem map (`shekyl-relay-privacy/src/stem_map/mod.rs`), the epoch scheduler and
fluff scheduler (`schedule.rs`), embargo derivation (`EmbargoTimer`,
`schedule.rs:420`), the noise cadence, `next_wake`, the origination roll and
the constants. C++ calls `shekyl_relay_zone_plan_relay_with_refresh(…)` and
receives `STEM` / `FLUFF_EPOCH` / `NO_ROUTE`; `dandelionpp_notify` states the
seam: stem-or-fluff is the zone's call, and re-deriving it at the transport
layer would put zone scheduling where the oracle cannot see it.

**The correct shape.** Before persisting any relay field on a pool record, ask
per field: *does `shekyl-relay-privacy` / `shekyl-relay` already hold the
authoritative value?*

- If yes → the store must **not** hold a second copy. A pool row that carries
  a value the Zone derives is two sources of truth for a privacy decision, and
  they will diverge across a restart.
- If no → it is evidence the Zone needs and does not keep, and the store holds
  it as **input to the Zone**, never as something the store or its readers
  interpret.

The test for each field: *if this value disagreed with the Zone's, which one
would be right?* Any answer other than "the Zone's" means the field is
misplaced.

**The audit, at source (`DRS_E1_SPOOL.md` SPL-17).** The Zone holds
per-**connection** and per-**epoch** state and returns a plan per call; it
holds **no per-transaction** relay fact and its own doc refuses to
(`shekyl-relay/src/zone/mod.rs:594–597`: *"retaining a per-transaction outcome
for a consumer to poll would put a second copy of a fact the txpool already
owns beside the txpool"*). `EmbargoTimer` owns the **distribution**; the pool
stamps the drawn **deadline** (`tx_pool.cpp:1298`). `StemWatch` holds a
transient per-transaction observation whose verdict lands in the pool
(`stem_watch.rs:194–206`; §92.5c item 1). So every relay field on the record
falls in the **second** branch — evidence — and the record is the sole
persistent home, not a copy. `SPL-Q7`'s persist-whole is right on that ground
and only on that ground. **What follows for E5:** the store's readers do not
branch on those fields; the relay loop that does is the Zone's job, taking
the record's fields as input — the C++ shape, in which `tx_pool.cpp` decides
re-relay timing from `last_relayed_time`, is policy in the pool.

**Drift looks like.** A `PoolRecord` carrying `relay_method`, an embargo
deadline and a stem assignment as first-class fields the store's readers
branch on — the C++ shape, which puts relay policy back in the pool the Rust
design spent a round removing it from.

---

## 3. `Local` is three properties, not one relay method

**The ruling.** [`DAEMON_RELAY_PRIVACY.md`](DAEMON_RELAY_PRIVACY.md) §92.4
unbundled the `Local` class:

1. **Provenance** — "this node originated it." **Permanent.** Never cleared:
   *"An originated entry's `Local` class is provenance and is not upgraded by
   a re-arrival of its own transaction."* The pin *"holds against a peer's
   assertion, and yields to proof of work."*
2. **Re-broadcast responsibility** — "this node still owes the network a
   relay." **Terminated by observation** — *"separately disarmed when the
   transaction is observed circulating."*
3. **Disarm** — the predicate that terminates it: F-10's *"this came back from
   somewhere other than where I sent it"* (§92.5c item 1, `StemWatch::seen` →
   `tx_memory_pool::on_stem_propagated`).

The C++ carries all three as one `relay_method::local` plus the
`observed_circulating` bit plus the origin-pin special case in `add_tx`
(`tx_pool.cpp:456–458`), and its ratchet clears `is_local` on a `Block`
arrival — intended for the *behaviour* (§92.4: "past that point the pin's
sign flips") but it takes the *fact* with it. "Has it been broadcast" and "did
we originate it" cannot be asked separately.

**The correct shape.** Three lifetimes, not one enum value.
`DRS_E1_SPOOL.md` `SPL-Q9` poses provenance (permanent; the store refuses an
update that changes it), phase (the ratchet — how it is travelling now — with
the pin that an originated entry never walks to `Stem`/`Fluff` and yields to
`Block`), and responsibility (`Armed` / `Disarmed`, originated entries only;
F-10's verdict writes `Disarmed`). **As built (2026-09-24, review on the
increment):** those three are one `RelayState`. The phase enum is chosen by
the provenance — `OriginatedPhase` is `Held | Block`, `ArrivedPhase` is
`Stem | Fluff | Block` — so the forbidden pairs have no value, and
responsibility is a field of the originated arm only. Permanence compares
`RelayState::origin()` (originated, or arrived over a zone), not the whole
state, so a phase step or a disarm is not an origin change. `upgrade` is the
strict forward step; an update stores a new phase only when it is that step
or the same phase. The disarm *timer* is the Zone's; the pool holds no timer.
The byte enum `RelayMethod` stays what it is — the FFI seam's word for an
arrival class or a routing plan — and is derived at the seam, not persisted.

**Drift looks like.** A single `RelayMethod` field that callers mutate to
record progress — `local` → `fluff` on first relay. One variable carrying
three lifetimes: exactly the C++ shape.

**Docs owed — discharged 2026-09-24:** the pool-side consequence of §92.4 is
this section and `DRS_E1_SPOOL.md` SPL-18; §92.4 carries a pointer here.

---

## 4. SPL-14 — no relay state is reachable by fall-through

**The finding.** `src/blockchain_db/blockchain_db.h:126–130`, in a comment
justifying a different decision: *"a zeroed record decodes to `fluff`, NOT
`none` (`get_relay_method` falls through state 0 to the `fluff` return)."*
An unreadable or zeroed relay byte resolves to the broadcast-to-everyone
phase (`blockchain_db.cpp:132–165`, `default: // error case`). On a chain
whose origin defence is the stem phase, a parse default discloses origin —
and the crate that owns fluff *scheduling* is not the one decoding the byte
that says *fluff*.

**The correct shape.**

- The relay discriminant is an enum with **no default arm and no
  fall-through**. `Fluff` is reachable only by its own byte.
- The decoder returns `Result`; an unrecognised discriminant is a codec error,
  not a value.
- Test: *every byte outside the pinned discriminants is an error; no byte
  reaches `Fluff` but its own.*
- `None` stays a legal, unreachable, non-relayable member with a one-line
  reason at the variant — it survives because the enum is byte-pinned at the
  FFI seam (`shekyl-relay/src/zone_route.rs:46–50`), not because it guards
  anything, and a mechanical cleanup that deleted it would shift every
  discriminant under that pin. It is not a field of the pool record (§3).

**Precedent to follow, in the same subsystem.** `shekyl-relay-privacy/src/stem_map/mod.rs:9–13`:
the port removed `boost::uuids::nil_uuid()` because the C++ used one sentinel
in three distinct roles — "this node is the source", "this stem slot is
dead", "no stem is available" — and every caller had to know which. *"Here
each of those is an `Option` in a distinct position."* Same disease, same
cure: a value that means several things becomes several things. An agent
shown a fix in the code it is working next to will follow it more reliably
than one shown a principle.

**Drift looks like.** `_ => RelayMethod::Fluff` anywhere, or a `From<u8>` that
cannot fail.

---

## 5. The peerlist — and the correction to "D++ pulls from the white list"

**The correction, verified at source.** It does not. `stem_map/mod.rs:6–7` —
*"which **outbound** peer a given source's stem traffic is pinned to for the
current epoch"* — and `:209` merges *the current outbound connection set* into
the map. So:

```text
gray/white peerlist  →  outbound selection  →  outbound connection set  →  D++ stem map
```

The peerlist feeds outbound selection; outbound selection feeds Dandelion++,
connectivity and sync alike. **Inbound connections never enter the stem path.**
Two steps, not one, and the distinction is load-bearing: a change to peerlist
policy reaches Dandelion++ only through whatever outbound selection does with
it. Told to an agent as "D++ pulls from the white list", it would produce a
peerlist change reasoned about as if it reached Dandelion++ directly.

**The peerlist rulings have homes, and this file points at them rather than
restating them:** [`P2P_3_SLICE_1_PEERLIST_BRIEF.md`](P2P_3_SLICE_1_PEERLIST_BRIEF.md)
(steering-revised 2026-09-23: white is populated only by a confirmed gray
draw; gray and white are disjoint and promotion *moves*; the file is an
unordered set of addresses and **restart puts every address on gray** — §7;
`--add-peer` **is gray**, and "ruling that an operator may assert white is a
steering decision, and it would be a third door" — §12) and
[`LV3_CONNECTION_OBJECT.md`](LV3_CONNECTION_OBJECT.md) §2.7.7 (an advert
means *"I reached this"*, never "you can reach this" — non-transitivity is a
feature of zero-trust gossip, not a defect) and §2.7.9 (divergent white lists
are a **privacy property**, not an accepted cost). Outbound is our security;
inbound is our service — our inbound set is chosen by whoever dials us and is
never a security input; diversity objectives belong to outbound selection.
LV-3 is designed from the rulings, not derived from `p2p_connection_context`.

**`--add-peer` — CLOSED 2026-09-24, against the review and for the brief.**
The review's draft of this section said *"`--add-peer` is the single
exemption that enters white without a dial."* The brief (§12) says
`--add-peer` is gray, and that letting an operator assert white "would be a
third door." The brief wins, and the reason is this file's own closing
section: white means *"I dialled this and it answered."* An operator
assertion is not a dial. Letting `--add-peer` enter white makes white mean
"I reached this" **or** "the operator said so" — one container, two meanings,
resolved by how the entry got there — the same defect as `nil_uuid` in three
roles and state 0 falling to `Fluff`, written into a document whose last
section is about exactly that. Gray serves the operator's actual intent
completely: the address enters the dial pool, gets dialled, promotes on
success. They wanted the peer *tried*, not *trusted*. **How it got in,
recorded because the failure has a shape:** the claim was cited from a past
session where it appears as the reviewer's own *suggestion*, not as a
ruling — and one subsequently ruled against. The borrowed-citation failure
with oneself as the lender. It was recorded as open rather than written in;
it is now closed. *(A second claim from the same source — a demand-driven
re-validation figure — had no ruling behind it and is not carried at all: an
unruled number in a reference is how a default gets chosen by whoever
implements first.)*

**Drift looks like.** A white list that accepts an inbound peer after a
back-ping (the inbound-derived endpoint is routed to **gray** at
`src/p2p/net_node.inl:2925`, `append_with_peer_gray`, with `last_seen = 0` —
"an unverified claim has never been seen"); anchors persisted as a separate
trusted file; a `PeerEntry` with a trust or score field; promotion implemented
as a copy so an address is in both lists.

---

## The common shape across all five

Each of these is the same defect wearing a different name: **a value that
means more than one thing, resolved by a default.** `nil_uuid` in three roles.
`relay_method::local` carrying three lifetimes. State 0 falling to `Fluff`.
`last_relayed_time` meaning `u64::MAX`, an embargo deadline, or a past relay
depending on a bit elsewhere. A peerlist entry meaning both "I reached this"
and "this is reachable."

The cure is the same every time, and it is already this codebase's house
style: make absence a case, give each meaning its own type, and let the
decoder refuse rather than default. `AtHeight<T>` and `AtIndex<T>`
(`shekyl-chain-rules/src/view.rs:63`, `shekyl-chain-store/src/store/at_index.rs:45`
— above-tip is a case, not a `None`), `TipState { recorded: Option<Tip>, … }`
(`store/read.rs:81` — an empty chain is a value, not `UINT64_MAX`),
`CurveTreeState::EMPTY` written by the seal (`codec/curve.rs:144` — absence
is SI-7, never a default), `Option<RMarket>` where the C++ returned `0`
(`DRS_E1_SARCH.md` SAR-8), `RelayZone::from_ffi_u8` provisioning an
out-of-range byte as the *worst* case rather than masking it to clearnet
(`shekyl-relay-privacy/src/zone.rs:68`), and the sentinel removal in
`stem_map` are all the same move. (The review named `TreeAfter`,
`SegmentAvailability` and `Tip::Empty`; none exists on this tree by those
names, so the list above is the verified one.)

When porting from the C++, the question is never "what does this field do"
but **"how many things does this field mean."**
