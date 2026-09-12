# `EndpointUpdate` — the round record (EU)

**Status:** **RULED** (round record) — dispositions `EU-D1`…`EU-D10` ruled
2026-09-11, recorded 2026-09-12. Nothing in this document is implemented
unless a disposition says so by PR number; as of the recording date only
`EU-D2`'s prerequisite (C0) has landed. **Read this before cutting B, C1 or
D.** The rulings were made in-channel by Rick and are quoted where the
words matter; the consequences are this document's.

**Unblocked by** — every input this round consumes is closed:

| Upstream | State |
|---|---|
| Carrier ruling — `EndpointUpdate = 4` on the bond-post vin, cold, zero-amount, epoch-open timing, two KATs | **RULED 2026-08-10**, [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §7 item 2 (carrier) — the shape this round implements, not reopens |
| Witness selection — the witness is the producer of block *h* | **CLOSED 2026-08-10**, same document, fork 2 |
| The client/server boundary for the archival path | **RULED 2026-09-11** (`EU-D1` below) — it re-derives fork 2 at the architecture level |
| C0 — the cold-authority selector as one Rust predicate | **LANDED 2026-09-12**, PR #703 (`4231518ca`); review pass in PR #711 |
| The named spec gap — which cold key a non-`JoinMarket` record verifies against | **RESOLVED** by C0's finding (`EU-D2`) |

**Freezes.** The endpoint field on the bond-post vin (a genesis-frozen consensus
wire) and the endpoint column on the bond record (LMDB). **Rule 42 does NOT
fire on the vin** — it governs tier-4 sealed `shekyl-engine-state` blocks, not
the consensus tx wire. It fires on the **wallet** half: `PENDING_POST_VERSION`
`10 → 11` when the wallet learns to persist a pending `EndpointUpdate`. The
LMDB `#define VERSION 12 → 13` is the schema guard — separate guard, separate
question (the `PC-D` row's phrasing). Getting this wrong is how B mis-aims the
bump; it is stated here so B does not have to re-derive it.

**Process.** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
cited: B and C1 move the FFI boundary and touch consensus; D changes a
KAT-frozen derivation. Identifier family **`EU-`**, registered at birth in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc); prefix
checked unique against C10 / C2 / CB / CEN / CR / CSR / CT / CU / CW / DQ / DRS /
DS / F / FL / GAP / GF / LV / MR / MS / MSW / OA / P / PC / PD / PR / PW / PWC /
PWD / Q12 / R18 / R2 / RC / RF / RK / RP / RT / S / SA / SCE / SH / SJ / SM / SO /
SP / TJ / VC / VG / WI / WP / X at the recording commit.

**Decision authority:** Rick. **Timing posture, in his words (2026-09-11):**
*"It's not like this is going to be released until this whole thing is
complete, so the timing is less important than it seems."* Sequence matters;
calendar does not.

---

## 1. What this round is, and is not

The 2026-08-10 carrier ruling was unusually complete: kind, family, amount
arms made unrepresentable, endpoint presence rule, cold authorization with the
family proxy explicitly broken, timing, and the laundering invariant as two
named tests. It left **one** spec gap — the cold key for a non-`JoinMarket`
record — and did not reach six implementation-shaping questions that any
author would otherwise decide silently at the keyboard. This round closes the
gap, decides the six, records two further rulings the sequence forced (the
client/server boundary; retired personas), and fixes the landing order.

It does **not** reopen the carrier ruling, does not touch the shard-assignment
gap (`-29505`, an unopened round of its own), and does not specify TJ-B — it
hands TJ-B its premises.

---

## 2. `EU-D1` — RULED 2026-09-11: the daemon is the client; no wallet talks to a wallet

**In Rick's words:**

> "From the typical coin perspective, the wallet is the client of the daemon
> in that the daemon is doing the p2p work and maintaining the blockchain
> state. However, from the ARCHIVAL perspective, the daemon would be a client
> of a remote wallet serving P so that it could check shards, verify a
> challenge, etc. But this is a special case, whereas the wallet is a client
> of the daemon is the typical case. **In no case should one wallet talk to
> another.** RPC is a separate layer on top of that base relationship."

**What it settles, and why it was already true.** Fork 2 of the challenge
mechanism (CLOSED 2026-08-10) made the witness *the producer of block h* —
"miners are the only population where being selected *is* proof of being
online at that instant" — and §9.4 says "miners are simply clients of it."
Miners run daemons. `EU-D1` ratifies at the architecture level what the
mechanism round forced at the selection level; nothing reopens. The
no-wallet-to-wallet clause is **satisfied by construction**: the only party
ever drawn is whoever produced block *h*, and there is no oracle for anyone
else's liveness to draw on instead.

**Consequences this round carries forward:**

1. **Discovery is a chain read.** The daemon already holds the chain, so
   "which persona holds shard *s*, and where is it" is a local lookup against
   the bond record — no gossip layer, no DHT, no new Levin message. That is
   the whole simplification the boundary buys, and it is why the endpoint
   lives on the record (`EU-D3`, `EU-D4`).
2. **The shard route stays HTTP-over-onion, not a P2P message.** The server is
   a wallet (`shekyl-p-host` / `shekyl-p-serve`), not a peer node; a daemon
   P2P message would make the wallet a P2P participant, which the boundary
   forbids in the other direction.
3. **The fetcher is a daemon subsystem, written in Rust** beside
   `shekyl-daemon-rpc` (rule 20; the countermand), reaching personas over the
   daemon's own Tor surface (`shekyl-tor-control-daemon`). Out of this round's
   scope — TJ-B's — but its home is fixed here.
4. **SP-T3 measured the wrong topology.** The dispersion spike is
   persona→persona onion; the protocol path is daemon→wallet. **Obligation on
   TJ-B, not an `EU-` disposition:** re-base the measurement daemon→wallet
   *before* promoting SP-T3 to challenge substrate, or W₂ is derived from a
   topology the protocol never uses. The index already notes the adjacent
   hazard (a single daemon makes both ends share a guard).
5. **RPC is a separate layer.** The shard fetch is not a wallet-RPC method and
   not a daemon JSON-RPC method; it is a daemon-initiated outbound fetch. The
   `-29505` refusal and its siblings live at the RPC layer and are not where
   this is solved.

---

## 3. `EU-D2` — RULED (resolved by C0's finding): the cold key is the record's committed `bond_spend_pk`, reached by widening the selector one arm

**The gap as the carrier ruling left it:** *"Spec detail to resolve: which cold
key a non-`JoinMarket`-posted record verifies against (`bond_spend_pk` is
present iff `JoinMarket` on the wire)."*

**The answer was already in the tree.** A value-out post authorizes against the
**record's committed `bond_spend_pk`**, never a vin-carried key (SA-2b forbids
the key on non-`JoinMarket` vins precisely because a vin-carried key is a
forgeable self-assertion); the authorizer rides the surface-A `pqc_auths` slot
and the pin ties it to the record (`db_lmdb.cpp` `set_archival_bond_value`
persists it). `EndpointUpdate` inherits that answer unchanged. What was
missing was not a key but a **selector** that could say so: until C0 the
"is this a cold post" decision was implied by which C++ arms happened to call
the pin, and described in prose — in three places — as *"`bond_debit > 0`, not
the post kind."* `EndpointUpdate` has `bond_debit == 0`, so under that prose it
would have authorized **hot**: exactly the stalemate the carrier ruling's
authorization clause exists to prevent.

**C0's finding (PR #703):** the prose never described the code. The Release
arm pins on kind, unconditionally, ahead of UB9; only `HoldingsUpdate` selects
on the debit term. The selector is now one exhaustive Rust truth table,
`requires_cold_authority(post_kind, bond_debit)`, and every consensus site
calls the composed `cold_authority_pin`. **C1 is one arm:**
`BondPostKind::EndpointUpdate => true`. It lands atomically with B under
[rule 07](../../.cursor/rules/07-consensus-atomic-cutovers.mdc), so there is no
window in which kind 4 exists and authorizes hot.

**Why C was split (Rick, 2026-09-11):** *"C0 — extract the predicate, no
behavior change. … C1 — add one arm. Three lines, lands atomically with B."*
The alternative — bundling a change to every value-out post's authorization
into the endpoint feature — was a false choice; C0 front-loaded the risky part
so a C++-caller break surfaces before the endpoint work depends on it. It
did: C0's own gate needed a statement-scoped call-site check before it could
match the wrapped call.

---

## 4. `EU-D3` — RULED: the endpoint is the raw 32-byte Ed25519 key, present iff `JoinMarket ∨ EndpointUpdate`, structurally mandatory on `JoinMarket`

**Encoding.** The v3 onion address is `pubkey ‖ checksum ‖ version`,
base32-encoded — everything but the key is derived. Storing the string would
put a parser and a canonicalization question on a genesis-frozen surface,
cost 56 bytes for 32 bytes of entropy, and admit non-canonical spellings that
differ as bytes and agree as addresses. Rules
[65](../../.cursor/rules/65-address-format-discipline.mdc) and
[42](../../.cursor/rules/42-serialization-policy.mdc) both point at the key.
**The address is a display form.** A reader reconstructs it; the wire never
carries it.

**Presence.** Present iff `post_kind ∈ {JoinMarket, EndpointUpdate}`, enforced
in `write` / `read_payload` alongside the existing `bond_spend_pk`-iff-`JoinMarket`
coupling — two fields, two couplings, one enforcement site. A `JoinMarket` vin
without an endpoint, or a `Release` / `Rebond` / `HoldingsUpdate` vin with one,
is unrepresentable on the wire, the same idiom as the amount arms.

**Mandatory on `JoinMarket`.** The carrier ruling's *"a bond without an
endpoint was the discovery gap"* reads as mandatory; it lands as a
non-`Option` field. There is no chain and no wallet, so there is no legacy
bond to accommodate — a bond without an endpoint cannot be constructed.

**On the record.** `ArchivalBondValue` gains a 32-byte endpoint column; written
at `JoinMarket` connect, overwritten at `EndpointUpdate` connect, **never
cleared** (`EU-D7`). LMDB `VERSION 12 → 13`.

---

## 5. `EU-D4` — RULED: the witness reads the endpoint from the drawable snapshot at epoch open, joined through the record by `p_id`

A persona accumulates one `JoinMarket` and *N* `EndpointUpdate`s. Discovery is
a chain read only if the witness reads **one place** — not a history walk. That
place is the drawable-set snapshot the challenge derivation already takes at
epoch open (`challenge_assignment.rs`, `DrawablePair { p_id, shard_id }`; §9.5
pin 1's canonical order). The pair is the sort key; the endpoint is **not** a
field on it — it joins through the bond record by `p_id`, one lookup, at the
moment the drawable set is snapshotted. This is the carrier ruling's *"the
drawable snapshot and the endpoint move together"* made concrete: an
`EndpointUpdate` that connects mid-epoch is record-effect at connect and
mechanism-effect at the next epoch open, exactly as `HoldingsUpdate` is.

Stated here rather than left to whoever writes the fetcher, because the
alternative — the fetcher walking the record's post history — is the design a
reader of the wire would reach for, and it is wrong.

---

## 6. `EU-D5` — RULED: rotation rate is unbounded, and cold custody is the brake

Zero economics means the only brakes on rotation are the transaction fee and
the friction of reaching cold custody, and the epoch-open timing rule makes
mid-epoch flapping invisible to the mechanism regardless. No bound. **Ruled
rather than left unasked**, because an unasked bound on a consensus surface is
the thing a later reader adds "to be safe" and then cannot remove.

The carrier ruling's stated cost stands and is the operator-facing text:
rotation requires the same custody used for releasing — the escape is not
automatable from the serving box. That is the correct trade, and it is the
bound.

---

## 7. `EU-D6` — RULED: enumeration is a design input, not a leak to tolerate

Publishing onion keys on chain makes the entire archival set a permanently,
publicly enumerable list of live services — every persona, forever, including
retired ones. That is the intended cost of chain-read discovery, and under
`EU-D1` it is stronger than a cost: **a daemon doing discovery needs the
persona set anyway.** Enumerability is an input the fetcher relies on.

What it obliges downstream, recorded so TJ-B inherits it as a premise:

- **TJ-H's guard→persona confirmation oracle changes character.** It
  previously assumed an adversary who already knew which `.onion` to probe;
  now everyone does. The fixed shard size (3,326,976 B) is the traffic
  signature, and the only mitigation is variable-length padding — which is a
  wire-format property and therefore **must be decided inside the frozen
  response semantics** (`RF-D4`'s layer), or it cannot be added later without
  a consensus-boundary change. `shekyl-p-serve` already solved the header
  half (hand-rolled HTTP so two personas are byte-identical at the header
  level, `RESPONSE_HEADER_NAMES` asserted complete); TJ-H is the same threat
  one layer down, and the endpoint is the right place to *emit* padding while
  the scheme lives in the frozen format because the witness verifies it
  against `R_k`.
- **Serve-side fetch rate-limiting becomes load-bearing, not hygienic.**
- The daemon's own circuit is now what confirms the oracle, so the
  rate-limit and the padding are daemon-facing controls as much as
  wallet-facing ones.

---

## 8. `EU-D7` — RULED 2026-09-11: refuse `EndpointUpdate` on a zero-bonded record; Release leaves the endpoint

**In Rick's words:** *"refuse EndpointUpdate on a zero-bonded record, and do not
clear the endpoint on Release."*

**Refuse, because rotation has no subject.** A Release preserves the record
row with `bonded_total == 0` (what `e2e_release_accepted_and_connected`
asserts), so a retired persona serves nothing and there is no endpoint whose
reachability matters. Permitting the post would create a mutation path on a
record the mechanism no longer reads. The refusal is a verify-time guard in
B's `verify_endpoint_update` — `bonded_total == 0 ⇒ refuse` — with its own
code, classified our-state (the record is what it is), not the sender's form.

**Do not clear, because clearing is a write on the policed path.** The
laundering invariant (`EU-D9`) exists to keep `EndpointUpdate` off the
standing-mutation path its sibling legitimately uses. Clearing the endpoint
on Release is a standing mutation on exactly that path; buying "no dead
addresses" with a write there is a bad trade.

**The harm from leaving them is smaller than it first reads — stated so no
one reopens it.** The endpoint is a field on a record, not an index. A
discovering daemon filters on drawability (`EU-D4`), so a dead address is
reachable only by someone deliberately reading non-drawable records. And
derivation-per-slot means a retired address is unlinkable to the operator's
next persona. "Enumerable forever" sounds worse than it is.

---

## 9. `EU-D8` — RULED 2026-09-11: D replaces the derivation and re-anchors the vector; it does not extend V1

**The problem.** `derive_p_hs_id_seed(master_seed, net, fmt, p_slot)` is
`p_expand_32(…, ARCHIVAL_P_HS_ID_INFO, p_slot)` — a labeled derivation with a
frozen vector (`docs/test_vectors/ARCHIVAL_P_DERIVE_V1`). Adding a rotation
term changes the preimage, and [rule 30](../../.cursor/rules/30-cryptography.mdc)
says one label never names two functions — so rotation cannot be added under
`ARCHIVAL_P_DERIVE_V1`. The reflex fix, "rotation = 0 reproduces today's
bytes," encodes absent-iff-zero into a preimage: the representational trick
that produces the next three-year-old comment.

**In Rick's words:** *"there is no chain and no user wallet, so **replace the
derivation outright and re-anchor the vector.** Mint the new label, rotation
always present, delete V1. Free today, a migration after genesis — the same
argument that decided the envelope arms."*

**Consequences.** A new label (`…-hs-id-ed25519-v2`, hyphen-normalized per
the existing convention), rotation index always present in the preimage, the
V1 vector directory **deleted** and a V2 minted with a fresh manifest. This is
a self-pinned (tier 3) vector under [rule 50](../../.cursor/rules/50-testing.mdc)
§"Regenerating a self-pinned vector is a decision, not a command," so **D's
first artifact is the decision-log entry** — written by this round, below —
and D's regenerator invocation cites it. The V1 manifest's own
`regeneration_command` predates that rule and is not gated on a citation; D
replaces the regenerator along with the vector rather than inheriting an
ungated one.

**Sequencing consequence.** Until D lands, no second address exists to rotate
to, so B+C1 land a wire nothing can yet produce an update for — see `EU-D10`.

**Decision-log entry:** [`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md)
§"2026-09-12 — `ARCHIVAL_P_DERIVE_V1` retired: `hs_id` derivation takes a
rotation index; vector re-anchored as V2 (`EU-D8`)".

---

## 10. `EU-D9` — RULED (carried from 2026-08-10, restated as B's acceptance): the laundering invariant is two tests

Carried verbatim from the carrier ruling because B is what makes it
checkable, and prose will not stop the shared-path mistake — the sibling
`HoldingsUpdate` legitimately carries standing-mutation code, and a
maintainer seeing two siblings in one enum will reach for the shared
record-update path.

- **KAT (a):** a record's `join_settlement_epoch`, bad-interval list,
  `bonded_total`, and holdings are **byte-identical** across an
  `EndpointUpdate`. Over `bond_connect.rs`, in the retention crate's test
  suite.
- **KAT (b):** a failure-window vector in which a persona at 10 accumulated
  misses **still slashes after rotating** — the attack stated as a test, the
  one that fails loudly if rotation is wired into the wrong branch. Fixture
  infrastructure exists (`gate4_lifecycle_kat.rs`,
  `attestation_settlement_window.rs`).

Both land **in B**, and both must be observed failing against a deliberately
mis-wired connect before they are trusted (rule 50; the C0 bites are the
pattern).

---

## 11. `EU-D10` — RULED 2026-09-11: the sequence, and the dispositions each step leaves behind

**In Rick's words:** *"C0 → A → B+C1 (atomic) → D."*

| Step | Lands | Disposition it leaves |
|---|---|---|
| **C0** | `requires_cold_authority` + `cold_authority_pin`; selector in Rust | **LANDED** #703; review pass #711 |
| **A** | this document; the decision-log entry; `EU-` registered; HELD rows flipped | this PR |
| **B + C1** (one PR, rule 07) | kind 4 in the retention enum, the C++ `archival_bond_post_kind`, and `shekyl-wire` (whose `Other(u8)` already parses it); the endpoint field and its couplings; the record column + LMDB 12→13; `PENDING_POST_VERSION` 10→11; `verify_endpoint_update` incl. the `EU-D7` refusal; the C++ connect arm; `EU-D9`'s two KATs; **and** the one predicate arm | **STAGED (rule 23)** — a deliberate callee-without-caller: the wire exists and nothing produces an update for it. Named consumers: D (the second address) and, for the *read* side, TJ-B's fetcher. In-policy under the disposition test because both consumers are named and the plan is live; recorded here so the next audit does not flag it |
| **D** | new label, rotation always present, V1 deleted, V2 minted; regenerator cites the entry | closes B's staging |

**Why D is last despite being a production prerequisite.** B+C1's staging is
safe (the predicate arm ships with the wire, so kind 4 never authorizes hot),
and D is the derivation change with the widest re-verification surface; landing
it last means it lands against a settled wire.

**Daemon C++ (Rick, 2026-09-11):** *"you may have to write the daemon C++ for
now — it will be rewritten, but I'd rather have it properly implemented and
rewritten than re-litigated from the daemon side when we do the Rust
cutover."* B's connect arm is written in C++ under that ruling, as the
existing pattern (a thin marshal onto a Rust verify), and ships with its
CSR-3a conformance record in the same PR — the C0 precedent (CEN-J13).

---

## 12. Out of scope, by name

- **Shard assignment** (`-29505`): its own unopened round. Not touched.
- **TJ-B** (the daemon-side fetcher and everything the read path needs): this
  round hands it `EU-D1`, `EU-D4`, `EU-D6` and the SP-T3 re-base obligation
  as premises. It does not specify it.
- **The credit-wire cutover deletion** (`ARCHIVAL_CREDIT_WIRE.md` §2's
  surface): separately scoped.
- **The `hs_id` service index** ("the daemon creates its service at index 0
  today"): the carrier ruling calls it an `EndpointUpdate` prerequisite; under
  `EU-D8` it is subsumed — the rotation index *is* the service index, and
  index 0 is the first address. No separate settlement needed.
