# `EndpointUpdate` — the round record (EU)

**Status:** **RULED** (round record) — dispositions `EU-D1`…`EU-D10` ruled
2026-09-11 and `EU-D11`…`EU-D13` ruled 2026-09-12 (B's readiness sweep),
recorded 2026-09-12. Nothing in this document is implemented unless a
disposition says so by PR number; as of the recording date only `EU-D2`'s
prerequisite (C0) has landed. **Read this before cutting B, C1 or
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
the consensus tx wire — and it does not fire in B at all: the pending block
stores each pending post as opaque wire `tx_bytes`, so nothing B changes is
a shape the snapshot gate reads. `PENDING_POST_VERSION` `10 → 11` lands with
the wallet producer that first persists a pending `EndpointUpdate`, in D
(`EU-D13`). The daemon has **two** guards, both in B: the record codec's own
`ArchivalBondValue::kVersion` `6 → 7` (a new column) and the LMDB
`#define VERSION 12 → 13` (a new column and a new table, `EU-D12`) — separate
guard, separate question (the `PC-D` row's phrasing).

**Process.** [`26-sub-pr-design-discipline`](../../.cursor/rules/26-sub-pr-design-discipline.mdc)
cited: B and C1 move the FFI boundary and touch consensus; D changes a
KAT-frozen derivation. Identifier family **`EU-`**, registered at birth in
[`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md) §2 per
[`94-tracking-index`](../../.cursor/rules/94-tracking-index.mdc); prefix
checked unique by `scripts/ci/check_index_prefix_uniqueness.py` over the 73
prefixes registered at the recording commit — the gate's count, not a hand-kept
list (a partial list reads as the population it is not).

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
   daemon's Tor surface. `shekyl-tor-control-daemon` is the crate that exists
   there; that it carries *outbound* is TJ-B's to confirm, not this round's
   claim. Out of this round's scope — TJ-B's — but its home is fixed here.
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
and the pin ties it to the record (`BlockchainLMDB::put_archival_bond_record` in
`db_lmdb.cpp` persists it). `EndpointUpdate` inherits that answer unchanged.
**"Cold" here is a custody tier, not a signing flow:** the principal-tier key
committed in the record, which the serving host does not hold. It is not an
air-gapped ceremony — cold *signing* is REJECTED permanently (decision log
2026-09-07) — and a cold-authority spend is an ordinary networked spend made
with a key kept off the serving box, the same act as a Release. What was
missing was not a key but a **selector** that could say so: until C0 the
"is this a cold post" decision was implied by which C++ arms happened to call
the pin, and described in prose — in three places — as *"`bond_debit > 0`, not
the post kind."* `EndpointUpdate` has `bond_debit == 0`, so under that prose it
would have authorized **hot**: exactly the stalemate the carrier ruling's
authorization clause exists to prevent.

**One clause of the source ruling reads the other way.** The shape sentence
in [`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §7
(:934 at the recording commit) says *"authorized by the persona's attestation
key"*; the same ruling's *"spec detail to resolve"* clause, quoted above, asks
which **cold** key. The attestation key is the identity key a serving host
holds — the drain the pin exists to close (`debit_auth.rs` header) — so the
second clause governs and the first is superseded here, not re-edited there:
this record is where the resolution lives.

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
differ as bytes and agree as addresses. Rule
[65](../../.cursor/rules/65-address-format-discipline.mdc) (an address is a
display form over a key) points at the key, and so does rule
[42](../../.cursor/rules/42-serialization-policy.mdc) where it applies — the
**wallet's** persisted copy of the field (Freezes, above), not the vin: a fixed
32-byte field versions cleanly; a string carries a format question into every
version bump.
**The address is a display form.** A reader reconstructs it; the wire never
carries it.

**Presence.** Present iff `post_kind ∈ {JoinMarket, EndpointUpdate}`, enforced
at every serializer — the retention `write` / `read_payload`, the C++ vin
`BEGIN_SERIALIZE_OBJECT`, boost, and JSON in both directions — alongside the
existing `bond_spend_pk`-iff-`JoinMarket` coupling, and beside the two
`EU-D11` adds. A `JoinMarket` vin without an endpoint, or a `Release` /
`Rebond` / `HoldingsUpdate` vin with one, is unrepresentable on the wire, the
same idiom as the amount arms. In `shekyl-wire` the kind is a per-kind
variant: `JoinMarket { bond_spend_pk, endpoint }` and
`EndpointUpdate { endpoint }` — the `Other(u8)` catch-all does not parse
kind 4, because the bytes after the kind differ.

**Mandatory on `JoinMarket`.** The carrier ruling's *"a bond without an
endpoint was the discovery gap"* reads as mandatory; it lands as a
non-`Option` field. There is no chain and no wallet, so there is no legacy
bond to accommodate — a bond without an endpoint cannot be constructed.

**On the record.** `ArchivalBondValue` gains a 32-byte endpoint column; written
at `JoinMarket` connect, overwritten at `EndpointUpdate` connect, **never
cleared** (`EU-D7`). Two guards move: the codec's `kVersion 6 → 7` and LMDB
`VERSION 12 → 13` (the latter also covering `EU-D12`'s table).

---

## 5. `EU-D4` — RULED: the witness reads the endpoint from the drawable snapshot at epoch open, joined through the record by `p_id`

A persona accumulates one `JoinMarket` and *N* `EndpointUpdate`s. Discovery is
a chain read only if the witness reads **one place** — not a history walk. That
place is the drawable-set snapshot the challenge derivation already takes at
epoch open (`challenge_assignment.rs`, `DrawablePair { p_id, shard_id }`; §9.5
pin 1's canonical order). The pair is the sort key; the endpoint is **not** a
field on it — it joins through the bond record by `p_id`, one lookup, at the
moment the drawable set is snapshotted. This is the carrier ruling's *"the
drawable snapshot (§4.1) and the endpoint move together"*
([`ARCHIVAL_CHALLENGE_MECHANISM.md`](ARCHIVAL_CHALLENGE_MECHANISM.md) §7, :934
at the recording commit) made concrete: an
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
code, classified as its exact sibling is: `HoldingsUpdate` on an unbonded
record is `SHEKYL_ARCHIVAL_BOND_POST_ERR_HU_RECORD_NOT_BONDED`, mapped to
`DropVerdict::PolicyOrState` (`rust/shekyl-ffi/src/archival_ffi/codes.rs:275`)
— our state, not the sender's form. B mirrors that mapping by name.

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

**The label is registered, and the registry is gated.**
`shekyl-archival-p-hs-id-ed25519-v1` has a row in
[`CRYPTO_DOMAIN_REGISTRY.tsv`](CRYPTO_DOMAIN_REGISTRY.tsv) (mechanism 2, HKDF
`info`, const `ARCHIVAL_P_HS_ID_INFO`), and `scripts/ci/domain_registry_gate.sh`
asserts every registered literal at its defining file — the v1 row fails the
moment the literal changes. So the registry row moves to v2 **in D's commit**,
not after it ([rule 30](../../.cursor/rules/30-cryptography.mdc)). The row is
`shekyl-live`, not `frozen-inherited`, so `FROZEN_DOMAIN_SEPARATORS.md` is not
in scope (checked at the recording commit: no `hs-id` row there).

**Sequencing consequence.** Until D lands, no second address exists to rotate
to, so B+C1 land a wire nothing can yet produce an update for — see `EU-D10`.

**Decision-log entry:** [`V3_WALLET_DECISION_LOG.md`](../V3_WALLET_DECISION_LOG.md)
§"2026-09-12 — `ARCHIVAL_P_DERIVE_V1` retirement AUTHORIZED: `hs_id`
derivation to take a rotation index; vector to be re-anchored as V2 (`EU-D8`)".

---

## 10. `EU-D9` — RULED (carried from 2026-08-10, restated as B's acceptance): the laundering invariant is two tests

Carried verbatim from the carrier ruling because B is what makes it
checkable, and prose will not stop the shared-path mistake — the sibling
`HoldingsUpdate` legitimately carries standing-mutation code, and a
maintainer seeing two siblings in one enum will reach for the shared
record-update path.

- **KAT (a) — structural, then parsed.** A record's `join_settlement_epoch`,
  bad-interval list, `bonded_total`, and holdings are byte-identical across
  an `EndpointUpdate` **by type**: under `EU-D11` the kind-4 vin carries no
  holdings and no amount term, so there is nothing for a connect to apply.
  The test that stands in for the assertion is a **parse** KAT: a kind-4 vin
  carrying holdings or a nonzero `bond_credit` / `bond_debit` fails to
  *parse* at every serializer (retention, C++ vin, boost, JSON) — not fails
  to verify. Its bite is a serializer that accepts the bytes.
- **KAT (b):** a failure-window vector in which a persona at 10 accumulated
  misses **still slashes after rotating** — the attack stated as a test, the
  one that fails loudly if rotation is wired into the wrong branch. Fixture
  infrastructure exists (`gate4_lifecycle_kat.rs`,
  `attestation_settlement_window.rs`). Its bite is a connect that touches the
  window.

Both land **in B**, and both must be observed failing against their bite
before they are trusted (rule 50; the C0 bites are the pattern).

---

## 11. `EU-D10` — RULED 2026-09-11: the sequence, and the dispositions each step leaves behind

**In Rick's words:** *"C0 → A → B+C1 (atomic) → D."*

| Step | Lands | Disposition it leaves |
|---|---|---|
| **C0** | `requires_cold_authority` + `cold_authority_pin`; selector in Rust | **LANDED** #703; review pass #711 |
| **A** | this document; the decision-log entry; `EU-` registered; HELD rows flipped | this PR |
| **B + C1** (one PR, rule 07) | kind 4 in the retention enum, the C++ `archival_bond_post_kind`, and `shekyl-wire` as per-kind variants (`EU-D3`); the endpoint field and the **four** presence couplings — `bond_spend_pk` iff JoinMarket, endpoint iff JoinMarket ∨ EndpointUpdate, holdings and the amount term absent iff EndpointUpdate (`EU-D11`) — at every serializer; `verify_endpoint_update` as the only verify accepting `credit == debit == 0`, incl. the `EU-D7` refusal; the record column (`kVersion 6→7`) + LMDB 12→13; the per-kind journal table and pop (`EU-D12`); the C++ connect arm with its CSR-3a record; the JoinMarket producer supplying the endpoint (a 32-byte accessor on `OnionIdentity`, which today holds only the base32 service id); `EU-D9`'s two KATs; **and** the one predicate arm | **STAGED (rule 23)** — a deliberate callee-without-caller: the wire exists and nothing produces an update for it. Named consumers: D (the second address) and, for the *read* side, TJ-B's fetcher. In-policy under the disposition test because both consumers are named and the plan is live; recorded here so the next audit does not flag it |
| **D** | new label, rotation always present, V1 deleted, V2 minted; regenerator cites the entry; the wallet producer for `EndpointUpdate` and, with it, `PENDING_POST_VERSION` 10→11 (`EU-D13`) | closes B's staging |

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

## 12. `EU-D11` — RULED 2026-09-12: the kind-4 vin carries exactly the endpoint; the amount term is absent, made unrepresentable at the serializers

**What the sweep found.** `BondTerm` is `Credit(NonZero) | Debit(NonZero)`;
the FFI conversion refuses `(0, 0)` (`ERR_NO_BOND_TERM`); every existing kind
carries an economic term (HoldingsUpdate-add requires `bond_credit == FLOOR`).
An `EndpointUpdate` is fee-funded with no bond term, so as A left it the
post could not balance.

**Ruled.** Term-absent iff `EndpointUpdate` — the third coupling in the §9.11
family — enforced **at the serializers**, not only at verify: a kind-4 vin
with a nonzero `bond_credit` or `bond_debit` fails to parse, so the
combination is unrepresentable in memory rather than refused later.
`verify_endpoint_update` is the only verify that accepts
`credit == debit == 0`; `BondTerm` itself is unchanged — a representable
zero term would undo what `NonZeroAtomicUnits` exists to prevent. The CT
balance for kind 4 is the plain equation with no bond term, through its own
FFI entry (`shekyl_archival_verify_endpoint_update_ct_balance`); the C++
bond-post caller selects the entry by `post_kind`, so no kind byte and no
term operands cross the boundary on the kind-4 path (see §15 for the
alternative this replaced).

**And holdings / `bonded_total_atomic` are absent too.** Both fields are
unconditional on the wire today and A did not rule them for kind 4. Ruled
**absent**: the kind-4 vin is `hybrid_public_key ‖ p_canonical_id ‖
post_kind ‖ endpoint` and nothing else. Two grounds, in Rick's words:
*mirror-and-verify "makes the escape hatch racy"* — a HoldingsUpdate landing
between assembly and connect would fail the rotation an operator is making
away from a compromised host — and *absent "makes KAT (a) structurally true
rather than checked"*. An ignored field is a laundering surface; an absent
one is not ignored, it is gone. Cost: a fourth presence coupling at the
serializers, mechanical against an idiom already applied.

---

## 13. `EU-D12` — RULED 2026-09-12: the endpoint pre-image gets its own per-kind journal table

Reorg pop must restore the previous endpoint. Release and HoldingsUpdate each
journal their record pre-image in a per-kind log table
(`archival_bond_unbond_log`, `archival_bond_holdings_update_log`), and
`EndpointUpdate` follows: `archival_bond_endpoint_update_log`, keyed like its
siblings, carrying the 32-byte prior endpoint. **Why not fold it into the
record's existing journaling** (Rick): *"folding endpoint pre-images into
bond-record journaling puts endpoint restoration on the path that also
restores value and holdings, so a pop bug that crosses fields turns a
rotation into a value error. Per-kind isolation is what keeps the mutation
classes apart."* The four-document obligation the coverage gate imposes on a
new table (`LMDB_SCHEMA.md` section and total 49 → 50, the
`DAEMON_REDB_STORE.md` registry row, the write-atomicity audit) is the gate
working as designed, not an argument.

---

## 14. `EU-D13` — RULED 2026-09-12: `PENDING_POST_VERSION` bumps with the producer, in D

The wallet's pending block stores each pending post as opaque wire
`tx_bytes` in a per-kind struct; B changes no persisted shape, and the
snapshot gate fails on change-without-bump, never on bump-without-change. A
bump in B would be a version with no schema behind it. The bump lands with
the wallet producer that first persists a pending `EndpointUpdate` — D's
scope, stated in the `EU-D10` row so D does not discover it there.

---

## 15. Rejected alternatives, in one place

Each is the decision and one line of reason. Where an entry supersedes text
this record carried at A, the SHA is the commit whose text it replaces; the
history is in PR #712, not here.

- **`shekyl-wire`'s `Other(u8)` "already parses" kind 4** — superseded
  (A, `91cc6d060`): once the endpoint field exists, `Other(4)` would read
  32 endpoint bytes as holdings. Per-kind variants (`EU-D3`).
- **`PENDING_POST_VERSION` 10 → 11 in B** — superseded (A, `91cc6d060`):
  no persisted shape changes in B. With the producer, in D (`EU-D13`).
- **KAT (a) as an assertion over `bond_connect.rs`** — superseded
  (A, `91cc6d060`): under `EU-D11` there is nothing for a connect to apply;
  the assertion became a type and the test became a parse KAT (`EU-D9`).
- **Term-absent enforced at the verify edge only** — rejected (B sweep,
  2026-09-12): validation where the carrier ruling asked for
  unrepresentability; the sibling coupling is enforced at the serializers.
- **Holdings / `bonded_total_atomic` mirror-and-verify on kind 4** —
  rejected (B sweep, 2026-09-12): a racy escape hatch, and a field with no
  use in the variant. Absent (`EU-D11`).
- **Fold the endpoint pre-image into bond-record journaling** — rejected
  (B sweep, 2026-09-12): puts endpoint restoration on the value/holdings
  restore path. Per-kind table (`EU-D12`).
- **A `post_kind` byte on the shared bond-post CT-balance export** —
  superseded (B, `228546879`): the export's other caller is the
  reward-emission arm, which is not a bond post and has no kind to pass, so
  the byte would have been an untyped sentinel in consensus code. The kind-4
  shape has its own FFI entry and the C++ caller selects by kind (`EU-D11`).

---

## 16. Out of scope, by name

- **Shard assignment** (`-29505`): its own unopened round. Not touched.
- **TJ-B** (the daemon-side fetcher and everything the read path needs): this
  round hands it `EU-D1`, `EU-D4`, `EU-D6` and the SP-T3 re-base obligation
  as premises. It does not specify it.
- **The credit-wire cutover deletion** (`ARCHIVAL_CREDIT_WIRE.md` §2's
  surface): separately scoped.
- **The `hs_id` service index** ("the daemon creates its service at index 0
  today"): the carrier ruling calls it an `EndpointUpdate` prerequisite. Rick's
  instruction (2026-09-11) was to check *whether it needs settling before this
  lands or whether index 0 is simply the answer*. **PROPOSED, not ruled:** under
  `EU-D8` the rotation index would *be* the service index, index 0 the first
  address, and no separate settlement needed. That is this record's reading,
  put to Rick at D's design pass; it does not carry the round's status.
