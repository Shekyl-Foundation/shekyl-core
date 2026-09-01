# SP-T3 serving skeleton — the PD-F-2 dispersion measurement


**Status:** measurement spike, opened 2026-08-03. SPIKE-F-1 **REFUTED AS
STATED**; SPIKE-F-12 **CONFIRMS AN ACCEPTED RESIDUAL** (both in the §2
substrate table, cited by id rather than line because this block's own
insertion moves every line below it) — the
tor entry-guard set is per-process/datadir, so one tor process means one guard
set sees every stem successor (§21.1). **Status corrected 2026-09-01:** this
line deferred to [`IMPLEMENTATION_INDEX.md`](IMPLEMENTATION_INDEX.md), which
carries no row for this spike — a dangling pointer found by the P2P-1 census
archaeology sweep ([`P2P_1_WIRE_CENSUS.md`](P2P_1_WIRE_CENSUS.md) §1). The
status is stated here instead, where the spike's own findings live.

**Branch:** `spike/sp-t3-serving-skeleton` · **Base:** `dev@146c7a9`
**Class:** measurement spike. Not TJ-B. Not consensus.
**Opened:** 2026-08-03

This document exists so a maintainer can close or definitively re-scope
[`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`](ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md)
§8.3, whose gate is a **measurement**, not an argument:

> Is `q ≥ 0.10` forceable on a 3.33 MB Tor-borne fetch inside
> `CHALLENGE_RESOLUTION_BLOCKS`? The threshold comes from `q_risk* = 0.1011`
> (§6.2); whether the deadline **forces** it is PD-F-2's dispersion measurement
> — **unmeasured**.

---

## ⚠️ Correction (2026-08-03, post-run) — the apparatus was non-conformant

**The spike's harness put two personas on the wire simultaneously behind one tor
daemon. The firewall forbids that**, and this document's first revision reported
the predicted consequence as if it were a discovery.

The ratified position, verified at source:

- **Multi-persona per wallet is real** — `PSlot` is *"the index into the staker's
  derive-forward persona set"* (`shekyl-types/src/lib.rs:273`,
  `ARCHIVAL_BOND_CONSTRUCTION.md` §10.2 **Model D**). The held set is
  `{personas with live bonds} ∪ {p_slot ..= p_slot + k}`, `k` default 2. A staker
  wallet routinely holds several persona bundles at once.
- **But the permission is conditional, and the condition is exactly
  co-activation.** `ARCHIVAL_BOND_CONSTRUCTION.md:667`, on why retired-but-bonded
  personas may coexist: *"dormant consensus balances (**not co-activation — no
  simultaneous wire activity — so the firewall permits it**)"*. Many held; **one
  on the wire.** The code agrees: `stake_engine.rs:767` `active: Option<PSlot>`.
- **`ARCHIVAL_FIREWALL_GATE6.md` §10.9 (`:1241`, ratified Round-2 exit pin,
  checked off `:1297`)** already requires *"separate Arti client instances with
  **non-overlapping guard sets**"* for `P`'s serving HS, `P`'s outbound broadcast,
  and the principal's traffic — because *"a shared guard lets a guard-level
  observer correlate `P` and principal **regardless** of own-node-vs-Dandelion"*.

**Consequences applied throughout this document:**

1. **SPIKE-F-1 is re-dispositioned REFUTED AS STATED** (§2). It did not discover
   that personas share guards; it built a configuration in which they do and
   measured a coupling the design **already accepts on purpose**
   (`TRANSPORT_PLAN:616`, *"correct as-is — do not 'fix'"*). Its data becomes
   **SPIKE-F-12: corroboration, no action, no routing** (§2a).
2. **The former "mitigation may be counterproductive" disposition is
   WITHDRAWN.** It argued against a ratified pin from a measurement of the
   forbidden configuration, and §10.9 had already weighed and ruled on that exact
   trade.
3. **`D*` is re-derived from the single-persona arms only** (§12.0b). The
   concurrency arm is labelled **non-conformant** and excluded from the verdict.
4. **SPIKE-F-10 is re-dispositioned as a *deterrence datum*** (§12.0d), not
   withdrawn. A measurement of the forbidden configuration is what lets the
   project **price** what it forbids — and the price lands on *both* axes at once
   (complete guard overlap **and** ≥ ×1.54 latency — a **floor**, see §12.0d), so
   co-serving is never the efficient choice. The single-persona reader-concurrency question is separate
   and survives as **SPIKE-F-11**.

**The serving rule, for the record:** **one persona serves per wallet.**
Multi-persona *holding* is real and necessary (retired personas' `bond_spend` keys
must stay derivable to unbond). An operator wanting several *serving* personas
uses **separate wallets**, and is advised to run them on **separate machines**
(each with its own, default-configured tor). The rationale is linkability *and*, independently,
**attack surface**: each co-served persona adds an inbound onion, intro points, a
descriptor, and a share of one process's failure domain — for a reward that comes
from its **bond**, not from sharing a host.

---

## 0. What this spike found, in one screen

| # | Finding | Severity | Verdict |
|---|---|---|---|
| **SPIKE-F-1** | ~~Two personas behind one tor share entry guards~~ | — | **REFUTED AS STATED** — the apparatus built a co-activation layout §10.9 forbids; not new information (§2) |
| **SPIKE-F-12** | `ADD_ONION` has no per-service isolation knob; guard sets are per-process/datadir. **This corroborates an accepted residual — it does not motivate action.** `TRANSPORT_PLAN:616` accepts the `P`↔principal guard coupling and explicitly forecloses separate instances | INFO | **CONFIRMS ACCEPTED RESIDUAL** — no action, **no routing** (§2a) |
| **SPIKE-F-13** | §10.9's named mechanism (**separate Arti client instances**) was **dead text**: Arti is not the path — we consume the Tor Project's Expert Bundle as an external process. **Five** sites rested on the abandoned anchor | LOW (doc hygiene) | **CLOSED** — maintainer ruled; correction pass applied to all five (§2b) |
| **SPIKE-F-2** | Two personas' onion services do **not** share introduction points | HIGH (as a *negative*) | **REFUTED (measured)** — halt condition §8.5 does not fire |
| **SPIKE-F-3** | `MaxStreamsCloseCircuit` is a **`Flag`**, not a `MaxStreamsCloseCircuit=1` argument; the argument spelling earns `512` from tor | MEDIUM | **CONFIRMED (measured)** |
| **SPIKE-F-4** | A production persona onion key belongs in `archival_p.rs`, not in a second cSHAKE256 path from the master seed | MEDIUM | **CONFIRMED (source)** |
| **SPIKE-F-5** | `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` claimed SP-T0a delivered `ADD_ONION`/`DEL_ONION`. It did not | LOW | **CONFIRMED (source)** — corrected in this branch |
| **SPIKE-F-6** | The persona descriptor is a **liveness oracle** with ~3 h granularity, and it is an irreducible floor of running an onion service | MEDIUM | **CONFIRMED (measured)** |
| **SPIKE-F-8** | Two personas' descriptors land on **disjoint HSDir sets** (16 each, zero overlap) — the "shared HSDir" axis SP-T2 flagged does not exist | MEDIUM (as a *negative*) | **REFUTED (measured)** |
| **SPIKE-F-9** | `.gitignore`'s bare `bin/` rule silently untracks **any Rust crate's `src/bin/`** — Cargo's conventional binary location | MEDIUM (repo-wide) | **CONFIRMED (CI)** |
| **SPIKE-F-10** | **The price of co-serving, on both axes at once:** complete guard-set overlap (privacy) **and** `D*` 28.57 s → 44.00 s, **≥ ×1.54** (throughput). A **floor, measured once at N=2 on C-tor from one vantage** — not a characterization. Not architecture — the **cost of the layout the design forbids** | MEDIUM | **RETAINED AS A DETERRENCE FLOOR** (§12.0d) |
| **SPIKE-F-11** | One persona under many simultaneous readers — **MEASURED** on four seed nodes in four regions. Reader concurrency does **not** materially degrade the persona (p50 10.9 s → 14.8 s across 4→32 readers); the tail is dominated by **circuit draw**, not by load | MEDIUM | **ANSWERED** (§18) — `q(120 s) ≤ 0.042` at every `N` |
| **SPIKE-F-16** | **Circuit-latency dispersion dominates everything else.** Identical requests to the same persona span **4.49 s → 133.05 s (30×)**; per-region medians agree within 2.7 s. `D*` is a tail statistic and is therefore **non-monotonic in load** | **HIGH** (methodological) | **CONFIRMED (measured)** (§18) |
| **SPIKE-F-17** | **The PoW client ceiling is a compile-time CLAMP, not a give-up.** The client solves at its own maximum and proceeds, so honest-client PoW cost is bounded by a **constant** — it cannot be driven arbitrarily high by service escalation. This **bounds SPIKE-F-15's coupling** | MEDIUM | **CONFIRMED (source)** (§19) |
| **SPIKE-F-18** | **PoW-enabled ≠ PoW-active.** Below escalation the service advertises **no `pow-params` at all** and honest clients solve **nothing** — enabling the defense costs a quiescent persona zero, and is invisible until actually attacked | MEDIUM | **CONFIRMED (measured)** (§19a) |
| **SPIKE-F-19** | **The fixed 3,326,976-byte payload is a guard→persona confirmation oracle.** A guard-holding adversary confirms *which* `.onion` its circuit carries by fetching the shard on demand (public + free + fixed-size = the signature is the payload). Turns the literature's "expensive" active-confirmation step nearly free. **Wire-format property ⇒ freezes at genesis** | HIGH | **TJ-B, not spike** (§20); recorded so it cannot drift past the §9.4 freeze |
| **SPIKE-F-14** | §6a's three inbound protections are all **per-connection**; **nothing bounds aggregate load**, and `MaxStreams` is per-*circuit* so it does not either. A ~100-byte request returns ~3.33 MB — **~33 000× egress amplification** | **HIGH** (general, every `P`) | **CONFIRMED (source)** — both levers now built (§16) |
| **SPIKE-F-15** | **PoW effort is adaptive (AIMD), so the DoS defense and the §8.3 margin are coupled — not independent as this report first recorded them.** `D*` was measured with PoW **disabled**; under escalation honest miners pay solve time and the distribution shifts toward the deadline | MEDIUM | **CONFIRMED (spec + measured on `dev`)** — immaterial at measured effort, **ceiling unmeasured** (§17) |
| **SPIKE-F-7** | D4's payload is a **cost, not a blocker**: ~5 h of one-time regtest mining plus a batched extraction | INFO | **REFUTED as a halt** |

Two charter halt conditions were pre-registered as likely and **neither fired**:
the v3 key encoding needs no invented conversion (§8.3 → see §3), and regtest can
produce a real shard (§8.2 → see §4).

---

## 1. Threat-tuple discipline (§5.1)

Every claim below states `T = ⟨who, capability, cost, priced-where⟩` or is
withdrawn. "An observer might notice X" is not a finding here.

The base threat model is inherited from
[`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md`](ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md) §7:
**C2** (network observer — guard-level plus timing correlation, the case Tor does
not defeat) and **C3** (infrastructure operator), with the patience multiplier.
The single question that section names is whether the adversary can tie the
**origin** of `P`'s network activity to the principal.

---

## 2. SPIKE-F-1 — **REFUTED AS STATED**: the apparatus built a forbidden layout

### What was claimed, and why it does not stand

The first revision reported that "two personas behind one tor share entry
guards" as a HIGH finding and the spike's principal output. **The measurement is
real; the finding is not.**

```text
persona 0 guards      : 7BBE05B2 843E20D6
persona 1 guards      : 7BBE05B2 843E20D6
GUARD_OVERLAP         : 7BBE05B2 843E20D6      <-- complete
```

Those two personas were **on the wire at the same time**, which
`ARCHIVAL_BOND_CONSTRUCTION.md:667` forbids: multi-persona holding is permitted
*because* it is "**not co-activation — no simultaneous wire activity**". The
apparatus created co-activation, and then measured the guard sharing that
`ARCHIVAL_FIREWALL_GATE6.md` §10.9 says follows from putting `P` traffic on a
shared Tor client.

So this is a **conformance failure of the apparatus against a ratified
requirement** — not new information about the architecture. §10.9 (`:1241`,
checked off `:1297`) already states the rule and already states the reason:

> "A shared guard lets a guard-level observer correlate `P` and principal
> **regardless** of own-node-vs-Dandelion (fork 1) — so isolation is the
> structural pin and origin-dilution … is a refinement on top of it, not a
> substitute."

### The disposition that compounded it — withdrawn

The first revision left the mitigation open, arguing one-tor-per-persona "may be
counterproductive: more guard sets means more independent guard draws." **That is
withdrawn.** It argued against a ratified exit pin using a measurement of the
configuration that pin forbids, and §10.9 had already weighed precisely that
trade and ruled the other way — on the ground that a shared guard defeats
dilution *regardless*, which makes isolation structural rather than a cost to be
traded off.

If the guard-multiplication argument is to be reopened at all, it must be
reopened **against §10.9, on §10.9's own terms**, as an amendment to a closed
Round-2 exit item — not carried forward as a fresh open question discovered by a
spike.

### What the persona↔persona axis is actually worth

Under Model D the realistic co-tenants on one host are, in descending order of
how continuously they exist:

1. **`P` (the one active persona) ↔ principal wallet** — always both. §10.9's
   primary target.
2. **`P`'s serving HS ↔ `P`'s outbound broadcast** — also continuous, and also
   named in §10.9.
3. **`P_old` ↔ `P_new`** — only during a slot move, and `stake_engine.rs:239`
   notes "most sessions … move the active slot at most once".

Persona↔persona co-activation, which is what this spike measured, is **not on
that list**. It is forbidden outright.

---

## 2a. SPIKE-F-12 — corroboration of an accepted residual. **Not an open item.**

> **Read this before acting on the measurement below.** It appears to motivate
> running separate tor instances. **It does not, and that remedy is explicitly
> foreclosed.** This section exists partly to stop a future reader doing what two
> earlier revisions of this document nearly argued for.

### The measurement

With C-tor, `ADD_ONION` exposes **no per-service isolation parameter**, and the
guard set is a property of the **process / `DataDirectory`** (persisted in the
datadir `state` file). Two onion services on one daemon drew **identical** guard
sets (2 of 2), while their introduction points (6+6) and HSDir sets (16+16) were
**disjoint**. So the coupling is **exactly guard-level** — the layers tor derives
per-service from the blinded key are unaffected.

### It was already decided, twice, and in the opposite direction to "fix it"

`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md:616`, under a heading that reads
***"Two notes recorded (correct as-is — do not 'fix')"***:

> **SP-T0 guard coupling is the deliberate §7 residual.** "One Tor process, never
> one circuit" (§13) means `P` and the principal share one **guard set** — exactly
> where §7's named residual (guard-level + timing correlation, the case Tor does
> not defeat) lives. Severing it means *separate Tor instances*, which is
> **worse**: a non-default config is itself a fingerprint to any guard observer (a
> weaker adversary than the correlator the shared guard exposes). **Accept the
> coupling; the doc states it so a future reader does not split instances.**

And `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` DQ-T0.7 (decided 2026-07-02), on the
`DataDirectory` choice:

> **Within-session** — the §7 residual (`P` and the principal share one guard) —
> is **unaffected** either way: same process, same guards.

### There is also no configuration surface to review

An earlier revision of this document suggested a "torrc-surface review" could
settle whether config alone suffices. **That suggestion is withdrawn: the design
refuses to have such a surface.** `actor.rs` passes six typed options
(`DataDirectory`, `ControlPort auto`, `ControlPortWriteToFile`,
`CookieAuthentication`, `SocksPort`, `Log`, plus test-only `DisableNetwork`) and
states why a free-form flag list is excluded — it can smuggle the safety
invariants open "directly, or indirectly via `-f <torrc>` / `+Option` append /
`--defaults-torrc`, which no denylist reliably covers." Future customization
arrives as further **typed knobs**. Reviewing a torrc surface means reviewing
something that deliberately does not exist.

### Disposition

**Corroboration, no action, no routing.** The measurement independently confirms
the premise `:616` asserts (same process ⇒ same guards) and *refines its scope*
(the coupling is guard-level only; intro points and HSDirs stay disjoint). That
refinement is the one genuinely new thing here, and it is useful for reasoning
about the residual's blast radius — not for reopening it.

**Explicitly not routed to `:1644`.** An earlier revision routed this to the
"§10.9 isolation enforcement mechanism (Arti config vs. policy)" carry. That was
wrong twice over: the coupling is accepted rather than open, and the carry is
premised on **Arti**, which is not the path (SPIKE-F-13).

---

## 2b. SPIKE-F-13 — §10.9's mechanism clause is dead text (doc hygiene, maintainer's call)

**Tor Project owns Tor; this project consumes the Expert Bundle as an external
process** — hash-pinned, driven over the control port. The spike ran against
exactly that. **So the Arti anchor never fires**, and text conditioned on it does
not describe a reachable future state.

Four sites rest on that abandoned anchor:

| Site | Text resting on Arti |
|---|---|
| `ARCHIVAL_FIREWALL_GATE6.md` §10.9 (`:1241`) | "separate **Arti client instances** with non-overlapping guard sets" |
| `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` DQ-T0.7 | reopen criterion **(b)**, which names the Arti anchor as its trigger |
| `ARCHIVAL_FIREWALL_GATE6.md` `:479` | carried "at-source **Arti** pin → transport PR" (GF-12) |
| `ARCHIVAL_FIREWALL_GATE6.md` `:1644` | "§10.9 isolation enforcement mechanism (**Arti** config vs. policy)" |

**§10.9's *intent* stands** — `P`↔principal isolation matters, and the guard layer
is where the residual lives. What is unavailable is its *named mechanism*, and
`TRANSPORT_PLAN:616` already records what is done instead: accept the coupling,
do not split instances.

### Ruled and applied (2026-08-03)

The maintainer ruled the correction pass. **All five sites are annotated in
place** — original text struck through and retained for history, never deleted,
with the supersession dated and the replacement position cross-referenced:

| Site | Applied |
|---|---|
| `FIREWALL_GATE6.md` §10.9 | Correction block above the bullet: **intent stands**, mechanism superseded, points at `TRANSPORT_PLAN`'s accepted-residual note and *"do not split instances"* |
| `FIREWALL_GATE6.md` `:479` | Arti at-source pin **RETIRED** — no consumer |
| `FIREWALL_GATE6.md` `:1644` | Enforcement-mechanism carry **CLOSED** — no mechanism is owed; the S-6 key-locality half stays carried |
| `SP_T0_TOR.md` DQ-T0.7 (b) | Arti half **retired**; the encrypted-mount half of (b) **stands** |
| `SP_T0_TOR.md` §6 anchor | Embedded-Arti **retired as a *remedy***, with the asymmetry stated: the *trigger* (SOCKS isolation unenforceable) remains real and DQ-T0.4 remains its detector, but **no replacement remedy is specified** — that is an open question for the round in which it fires, and the answer is not "embed Arti" |

The fifth site was not in the original enumeration; it is `SP_T0_TOR.md` §6's
"embedded Arti (**the §10 anchor**)" — literally the anchor declared dead, so the
ruling covers it. It is the one place where care was needed: retiring a *remedy*
must not silently retire the *trigger* it answered, so the annotation separates
them explicitly rather than striking the whole bullet.

**Gate:** `scripts/ci/check_doc_links.py` — all relative links resolve.

---

## 3. SPIKE-F-2 — intro points are **not** shared (halt §8.5 does not fire)

The charter pre-registered intro-point sharing as a halt that "may invalidate the
spike's architecture." The six introduction points of persona 0 and the six of
persona 1 are **disjoint** (data in §2 above). Tor establishes an independent
intro-point set per service, so a client of persona A learns nothing about
persona B from the intro points it uses.

**Verdict: REFUTED.** The feared direct cross-persona linkage does not exist, and
the spike's one-tor-many-personas architecture survives. This is reported with
the same prominence the charter demanded for the positive result, because a
negative on a pre-registered halt is exactly as load-bearing as a positive.

---

## 4. SPIKE-F-7 — D4 is a cost, not a blocker

Both halves of the charter's pre-flight were answered on the box:

**Can regtest produce ≥ 25 992 leaves in reasonable wall-clock?** Yes.
Measured at `--fixed-difficulty 1`:

| height | s/block | `leaf_count` | tree depth |
|---|---|---|---|
| 201 | 0.645 | 141 | 1 |
| 708 | 0.674 | 648 | 1 |
| 1 401 | 0.658 | 1 341 | 2 |
| 2 438 | ~0.69 (cumulative) | ~2 378 | 2 |

`leaf_count` tracks height 1:1 behind a **constant ~60-block maturity lag**
(`DEFAULT_LOCK_WINDOW`), so the slope holds and extrapolation is sound. Target
height ≈ 25 992 + 60 ≈ **26 052** for the leaf bytes; add the freeze gate
(`tip − end_block_height ≥ SPENDABLE_AGE(60) + REORG_MARGIN(720)`) → ≈ 26 832 if
the `R_k` record is wanted too. At the measured rate that is **≈ 5 hours of
one-time mining**.

> **A measurement error worth recording.** The first rate probe omitted
> `--fixed-difficulty 1`, leaving the daemon doing real RandomX PoW at ~20 s/block
> — a 30× overstatement that would have turned a 5-hour cost into a 6-day one and
> very likely produced a spurious halt. The regtest harness's own spawn arguments
> (`regtest_e2e.rs`) were the source of truth.

**Does an extraction path exist?** Yes, and it is **batched**, not 684 round
trips: `COMMAND_RPC_GET_CURVE_TREE_PATH` takes a *vector* of `output_indices` and
returns the whole leaf-chunk for each. Verified live: 50 in-range indices → 50
chunk blobs. The daemon rejects an entire batch containing an out-of-range index,
so a short extraction cannot pass unnoticed.

One correctness point the extractor does not paper over: `chunk_outputs_blob`
carries compressed **Ed25519 points**, while a curve-tree leaf is
`construct_leaf`'s `O.x ‖ I.x ‖ C.x ‖ h_pqc` over Wei25519 x-coordinates. Serving
the blob verbatim would serve real chain data that is nonetheless *not what a
persona archives*, so the conversion runs locally through the same function the
wallet path uses. The blob's `I` is skipped rather than trusted —
`construct_leaf` re-derives `I = Hp(O)`, so a daemon/local disagreement surfaces
as a mismatch instead of being baked into the fixture.

**No synthetic fallback exists anywhere in the crate.** `ShardFixture::load`
refuses a missing or wrong-sized file with a message naming the remedy.

---

## 5. The v3 key encoding — halt §8.3 does not fire

tor's `ADD_ONION ED25519-V3:` `KeyBlob` is the **expanded** secret key, defined by
the control-spec as *"the concatenation of the 32-byte ed25519 secret scalar in
little-endian and the 32-byte ed25519 PRF secret."* The charter flagged this as a
possible halt.

Seed → expanded is **RFC 8032 §5.1.5 itself** — `SHA-512(seed)`, clamp the low 32
bytes — which is what `ed25519_dalek::SigningKey` does internally and what tor
does to its own generated seeds. It is the *definition* of an ed25519 key's
expansion, not a bridge invented between two formats.

**Verified against the pinned binary rather than argued.** The spike derives a
key, computes the v3 address independently
(`base32(pubkey ‖ SHA3-256(".onion checksum" ‖ pubkey ‖ 0x03)[..2] ‖ 0x03)`),
hands the expanded blob to a real tor, and asserts tor's returned `ServiceID`
matches. It does, for both personas, against Tor Expert Bundle 15.0.17 — whose
SHA-256 matches `binary.rs`'s `CURRENT_PIN` exactly, so the whole measurement
rides the production hash-pin gate rather than a test bypass.

**The trap this check exists to catch is real.**
`Scalar::from_bytes_mod_order(clamp_integer(b))` reduces mod ℓ, and a clamped
integer is ≥ 2²⁵⁴ > ℓ — so `scalar.to_bytes()` is *not* the clamped bytes tor
wants. Deriving the blob from a dalek `Scalar` would yield a valid key at a
**different** address, and the persona would be unreachable at the address it
advertises, with no error anywhere.

---

## 6. SPIKE-F-4 — the derivation is in the wrong crate (and cannot be fixed here)

The charter specified a cSHAKE256 separator "in the shape of `id.rs`'s
`P_CANONICAL_ID_CUSTOMIZATION`". That shape belongs to a **public-id** derivation;
this is a **secret** derivation from the master seed — and
`shekyl_crypto_pq::archival_p` declares itself *"the single source of truth for
how a Shekyl archival staking persona derives its keys from a wallet's
`master_seed_64`"*, via HKDF-SHA-512 with versioned `ARCHIVAL_P_*_INFO` labels,
frozen and KAT-pinned under `ARCHIVAL_P_DERIVE_V1`.

A production onion key belongs there, as one more `L=32` label. It is **not** done
here because that is an additive change to a genesis-frozen, cross-arch
KAT-pinned module — a design round of its own, and outside this charter's file
list.

**Reopen criteria (rule 21).** The spike module is deleted and the derivation
moves to `archival_p.rs` when *either* SP-T3 proper begins implementation *or* any
consumer outside this spike needs a persona onion key — whichever is first. The
re-evaluation shape is an `ARCHIVAL_P_DERIVE_V1` amendment round: new info label,
regenerated vectors under `docs/test_vectors/ARCHIVAL_P_DERIVE_V1/`, `aarch64`
qemu lane green. Until then the customization string spells `-spike-` so keys
produced by this path can never be silently inherited as canonical.

---

## 7. SPIKE-F-6 — the descriptor is a liveness oracle (§5.3)

A persona's HS descriptor is public by construction: it must be, or clients could
not reach the service. Its presence, absence, and republication cadence therefore
leak whether that persona is online.

`T = ⟨`
- **who:** an HSDir-observing adversary, or anyone who can fetch the descriptor
  (which is anyone who knows the address — and the address is public to every
  client of the persona, including every drawn miner);
- **capability:** observe presence/absence of a descriptor over time;
- **cost:** ~free for a known address (a periodic fetch); running HSDirs to
  enumerate is more expensive but the persona's own clients need no enumeration;
- **priced-where:** not currently priced in transport plan §7, which is a gap
  this finding fills.
`⟩`

**Granularity.** The descriptor carries `descriptor-lifetime 180` (minutes) —
read directly from a live service's own descriptor via
`GETINFO hs/service/desc/id/<addr>`. So observable downtime is bounded below by
roughly a **3-hour** window plus the republication cadence: an adversary learns
"P was offline somewhere in this ~3 h bucket," not "P was offline from 14:02 to
14:09."

**Why this matters economically.** Under a sliding-window slash, "P was offline
between T1 and T2" is actionable intelligence — it tells a competitor when to
concentrate challenges, and it tells anyone when the persona's operator sleeps.

**Is it reducible?** No. Publishing a descriptor *is* how an onion service is
reachable, and reachability is the persona's obligation (GATE2 §3.4: *"P must be
reachable at H_fire"*). A persona that hid its descriptor would be unreachable,
which is the thing it is bonded not to be.

**Disposition: this is an irreducible floor, and it is named as a floor** — the
same posture `DAEMON_RELAY_PRIVACY.md` takes with the Dandelion Theorem-2 result.
It is not a defect to fix; it is a property to state, so that no later design
assumes persona liveness is private. The one lever that *is* available is the
3-hour granularity itself: coarse buckets are much weaker intelligence than
precise timestamps, and nothing in SP-T3 should narrow them (for instance by
adding a health endpoint — which is why `serve.rs` has exactly one route).

---

## 8. Remaining §5.2 axes — honest verdicts

SP-T2's flag (`ARCHIVAL_BOND_2D2_SP_T2_FETCH.md`:134) named three serving-side
axes to enumerate: descriptor-publication timing, the **shared HSDir set**, and
introduction-point reuse. All three are measured below.

| Axis | Verdict | Evidence |
|---|---|---|
| Shared introduction points | **REFUTED** | Disjoint 6+6 sets, measured (§3) |
| Shared entry guards *(between two co-active personas)* | **MEASURED, BUT UNDER A FORBIDDEN LAYOUT** | Identical 2-guard set — but co-activation is ruled out by `ARCHIVAL_BOND_CONSTRUCTION.md:667`, so this is not an architectural finding. Re-dispositioned in §2; the mechanism fact it does support (C-tor has no per-service knob) is **SPIKE-F-12**, §2a. |
| Shared HSDir set | **REFUTED** | Each persona uploaded its descriptor to **16 HSDirs; the two sets overlap in zero relays.** A v3 descriptor's directory position derives from the blinded key, which differs per service, so this is theory confirmed by measurement rather than luck. **No single HSDir sees both personas' descriptors.** |
| Correlated descriptor publication timing | **CONFIRMED (weak), and weaker than expected** | Two personas added **0.043 s** apart began publishing **0.98 s** apart — a tight, genuinely correlated window. But the HSDir result above blunts it: exploiting the correlation requires observing **≥ 2 of the 32 distinct directories** the two descriptors land on *and* correlating across them, because no directory sees both. Combined with the fact that two unrelated services starting at once on a busy directory look identical, this is a real-but-weak channel, not a break. `T = ⟨`multi-HSDir operator; sees upload times at the directories it runs; cost = running a meaningful fraction of the HSDir ring; priced in the C2/C3 bucket`⟩`. |
| Co-serving penalty *(deterrence floor, not architecture)* | **QUANTIFIED AS A LOWER BOUND** | Doing the forbidden thing costs **both** axes at once: complete guard overlap (2/2) **and** ≥ ×1.54 on `D*`. **Floor, not characterization** — one run, N=2, C-tor, single vantage. See §12.0d. Distinct from **SPIKE-F-11** (one persona, many readers), which is conformant and **unmeasured**. |
| `MaxStreams` **exhaustion** on A observable at B | **UNMEASURABLE-HERE** | Distinct from the contention row above and **not claimed either way**. Deliberate flooding to the stream cap, distinguished from ambient variance, needs a controlled load generator and a quiet baseline this spike does not have. Contention at concurrency 2 is not evidence about the exhaustion path. |
| Error responses fingerprint the shared backend | **REFUTED (by construction)** | `serve.rs` renders one identical 404 for every non-matching request — wrong path, wrong method, malformed — asserted by `every_non_route_gets_one_identical_error`. Two personas' success headers are asserted byte-identical by `two_personas_are_header_identical`, and the complete header set is pinned to `content-type` + `content-length` (no `server`, no `date`, no `etag`, no `accept-ranges`). |

---

## 9. `ClientAuth` — deferred, with named reopen criteria (§5.4, rule 21)

**Rejected for this spike.** Client authorization on the onion would restrict who
can reach a persona. It is out of scope because the measurement needs an
*unrestricted* fetch path (a drawn miner is an arbitrary client, and §9's ruling
is that the miner uses *the same mechanism any wallet uses*), and adding
authorization would measure a different protocol.

**Reopen criteria — reopen `ClientAuth` as an access-control mitigation before
TJ-B if any of:**

1. **Intro-point sharing is found** under a configuration this spike did not test
   (more than two personas; a restarted tor reusing intro points; `Detach`ed
   services). §3 refutes it for two personas on one fresh tor, and that is the
   full extent of the claim.
2. **Descriptor enumeration proves cheap** — specifically, if an HSDir-side
   enumeration attack is demonstrated that recovers persona addresses without
   already knowing them, converting §7's oracle from "per-known-address" to
   "population-wide."
3. **The §8 `MaxStreams` axis resolves against independence** — i.e. a controlled
   experiment shows one persona's load measurably degrades a co-hosted persona,
   making unrestricted access a cross-persona DoS amplifier.

**Re-evaluation shape:** an SP-T3 design round taking the measurement that
triggered it as input, deciding between `ClientAuth` and per-persona tor
instances (§2's open question), since both address the same underlying
"co-hosted personas are coupled" problem.

---

## 10. The measurement's own adversary (§5.5)

This measurement is an argument about a consensus deadline, so its own threat
model matters.

**Can an adversary manipulate the distribution being measured?**

- **A hostile guard** can throttle or delay all of this host's traffic. Since both
  personas share guards (§2), a hostile guard biases *every* arm simultaneously.
  The spike **cannot** detect this: from inside, a slow guard and a slow network
  are indistinguishable.
- **A congested rendezvous** inflates the tail. Ambient and unattributable; it is
  part of what the measurement is *for*, but a single vantage point cannot
  separate "the network was congested that day" from "the network is like this."
- **Deliberate serving-side throttling to sit just inside the deadline** is a real
  strategy for a *bonded persona* under TJ-B (serve just fast enough to pass,
  never faster). This spike's serving side is honest by construction, so the
  measured distribution is an **upper bound on performance**, i.e. a *lower* bound
  on `q`. A hostile persona would make `q` worse, never better. **This direction
  is favourable to the conclusion and should be stated when the number is used.**
- **A hostile client** (the drawn miner) could under-report its own latency to
  frame a persona. Out of scope here — that is TJ-B's attestation problem, and
  §9.4(iii) already answers it topologically.

**What this measurement therefore does not prove:** that any *particular* fetch
in production will complete in the measured time. It characterises one vantage
point's view of the real Tor network over one window.

---

## 11. Environment, stated plainly (§6.4)

- **One vantage point:** a single residential/commercial host, one autonomous
  system, one guard set. Tor circuit latency depends heavily on the guard draw,
  and this run's guards are fixed for its duration.
- **One time window.** Circuit-latency dispersion is *time-varying*; a sample that
  does not span diurnal variation understates the tail.
- **One tor version:** Expert Bundle 15.0.17 (tor 0.4.9.11), hash-pinned.
- **Real Tor network**, not a private testnet: the rendezvous, the guards, and the
  intro points are all real public relays.

**Generalizing to a globally distributed miner population is not supported by a
single-vantage measurement.** A miner in a poorly-connected region, or one whose
guard draw is worse, will see a heavier tail. The honest reading of `D*` below is
therefore as an **optimistic bound**: the real population's `D*` is at most this,
probably lower.

---

## 12. PD-F-2 results

**Payload: a real archival shard.** 3 326 976 bytes — 25 992 leaves × 128 B —
extracted from a regtest chain mined to height 26 344 (`leaf_count` 26 218).
Not synthetic; the crate has no synthetic path.

**Environment:** Tor Expert Bundle 15.0.17 (hash-pin verified against
`CURRENT_PIN`), real public Tor network, single vantage point. Descriptor
publication took 32.2 s and is **excluded from every arm**.

### 12.0 The cold arm — the result the gate turns on

```text
n = 60, successes = 59, completion rate = 0.9833
failures: 1 × Truncated          (apparatus-class, not a network timeout)

  p50  =  14.71 s
  p75  =  23.22 s
  p90  =  28.99 s
  p95  =  32.75 s
  p99  =  39.27 s

D* = 28.57 s     (q(D) ≥ 0.1011 for all D ≤ D*)

warm-up check: first-quarter p50 = 13.97 s, last-quarter p50 = 16.17 s
               ratio 1.16
```

**The warm-up check came back clean, in the safe direction.** The concern was
that a "cold" arm hitting one persona repeatedly might warm via descriptor
caching or rendezvous reuse, making its tail optimistic and inflating `D*`. The
measured ratio is **1.16 — the arm got slightly *slower*, not faster.** Whatever
drift exists is conservative: it can only depress `D*`, never inflate it. The
unsafe bias is empirically absent rather than argued away.

### 12.0a Inverting against a **block-denominated** deadline — the decisive step

`D*` is in seconds; TJ-C's deadline is in **blocks**. Shekyl's target block time
is **120 s** (`config/consensus_constants.json`: `daa_target_seconds = 120`,
independently corroborated by `shekyl_blocks_per_year = 262800` →
31 536 000 / 262 800 = 120). The smallest deadline a block-granular rule can
express is therefore **one block ≈ 120 s**, which is **4.2 × larger than `D*`**.

Evaluating `q(D)` from the cold arm at every candidate:

| Deadline | `q(D)` | vs `q_risk* = 0.1011` |
|---|---|---|
| `D* = 28.57 s` | 0.1167 | ≥ q\* — **forces** |
| **1 block (120 s)** | **0.0167** | **< q\* — does *not* force** |
| 2 blocks (240 s) | 0.0167 | < q\* |
| 10 blocks (20 min) | 0.0167 | < q\* |
| `CHALLENGE_RESOLUTION_BLOCKS` = 10 000 blocks (≈ 14 d) | 0.0167 | < q\* |

At one block and beyond, `q` has already collapsed to the **outright-failure
floor of 0.0167** — a single truncated response in 60, and an apparatus-class
failure at that. No fetch in the arm exceeded 40 s, so every block-denominated
deadline is far out on the flat part of the curve.

### 12.0b The conformant arms — `D*` re-derived, concurrency arm excluded

**Only the single-persona arms are conformant.** The 2-persona concurrent arm ran
the co-activation layout §10.9 forbids (see §2) and is **excluded from the
verdict**.

| Arm | Conformant? | `n` | p50 | p90 | p99 | `D*` | `q(120 s)` | at 1 block |
|---|---|---|---|---|---|---|---|---|
| Warm circuit, single persona | ✅ | 60 | 8.21 s | 13.46 s | 20.13 s | 13.22 s | 0.0167 | does **not** force |
| **Cold circuit, single persona** | ✅ | 60 | 14.71 s | 28.99 s | 39.27 s | **28.57 s** | 0.0167 | does **not** force |
| ~~2 personas concurrent~~ | ❌ **non-conformant** | 60 | 21.65 s | 44.04 s | 72.29 s | ~~44.00 s~~ | ~~0.0000~~ | *excluded* |

**`D* = 28.57 s`, from the cold single-persona arm** — the pessimistic conformant
case, and the faithful model of a drawn miner (circuit build + rendezvous inside
the timed path, a different client each fetch).

**Excluding the non-conformant arm strengthens the conclusion rather than
weakening it.** That arm was the *slowest* of the three, so it produced the
*largest* `D*` (44.00 s). Dropping it moves the governing `D*` **down** from
44.00 s to 28.57 s — further below the 120 s block boundary, widening the margin
from 2.7× to **4.2×**. The verdict therefore holds *a fortiori*: the forbidden
layout has more shared-process contention than production will, so a conformant
deployment is faster, not slower.

The first revision's "even the worst arm clears with room" reassurance **leaned
on the non-conformant arm and is withdrawn.** The correct statement is that the
verdict rests on the two conformant arms alone and does not need the third.

**Apparatus cross-check passed exactly.** The endpoints report **181** requests
served against 180 counted fetches plus the one reachability probe — so no
"success" came from anywhere other than the persona it was attributed to. (This
is an integrity check on the harness, and is unaffected by the conformance
question.)

### 12.0c The drift detector fired where it should — which is what makes its silence meaningful

The **warm** arm tripped the warning at ratio **0.57** (first-quarter p50 12.26 s →
last-quarter 6.93 s). That is **correct and expected**: the warm arm reuses one
client id by design, so tor progressively warms its circuit. The warning's text
is conditioned on being the cold arm, and it is not.

The value of that firing is as a **positive control**. A drift check that never
fires is indistinguishable from a broken one, and the cold arm's clean **1.16**
would then be a vacuous negative. Because the same detector fires at 0.57 on an
arm that genuinely warms and reads 1.16 on the arm that must not, the cold arm's
result — the one `D*` rests on — is a *measured* absence of warming, not an
unexercised assertion.

### 12.0d SPIKE-F-10 — the price of co-serving, and why the number is worth keeping

The first revision called this a discovery; the second withdrew it as a
forbidden-layout artifact. **Both were wrong, in opposite directions.** A
measurement taken under a forbidden configuration is not evidence about the
architecture — but it is exactly the thing that lets the project *price* what it
forbids.

#### The serving rule, stated plainly

**One persona serves per wallet.** Multi-persona *holding* is real and necessary
(Model D — retired personas' bonds sit on chain and their `bond_spend` keys must
remain derivable to unbond later), but **serving** is singular. An operator who
wants several serving personas runs them **on separate wallets**, and is advised
to run them on **separate machines**, each with its own default-configured tor.
*(Separate machines, not two tor clients on one host — the latter is the
deviation-from-defaults fingerprint `TRANSPORT_PLAN:616` objects to.)*

The rule is not only the linkability argument this spike measured. It is also, and
independently, **attack surface**: each co-served persona adds an inbound onion,
its intro points, its descriptor, and its share of one process's failure domain —
**for no benefit that co-location provides.** The reward from a second persona
comes from its *bond*, not from sharing a host with the first. Co-location buys
operational convenience and nothing else.

#### What it costs to do it anyway — both axes, measured

| Axis | Single persona (conformant) | Two co-served | Penalty |
|---|---|---|---|
| Entry guards | *n/a* | **2 of 2 shared — complete overlap** | privacy: a guard-level observer sees both personas' traffic from one origin |
| p90 latency | 28.99 s | 44.04 s | **+52 %** |
| `D*` | 28.57 s | 44.00 s | **≥ ×1.54** (floor) |
| Completion | 0.9833 | 1.0000 | *(no failure penalty — the cost is latency, not loss)* |

#### ⚠️ The ×1.54 is a **floor**, not a characterization

Cite it as *"at least this bad, measured once."* It is:

- **C-tor-specific** — a property of how one tor daemon multiplexes two onion
  services, not a general statement about Tor;
- **N = 2** — the smallest possible co-serving case, and the penalty is not
  assumed linear (or of any form) beyond it;
- **one vantage, one run, one time window** — no error bars, no diurnal coverage.

The honest reading is a **lower bound on the throughput penalty**: co-serving cost
**at least** this much here, and there is no reason to expect a larger deployment,
a worse-connected host, or a different tor version to do *better*. It must not be
quoted later as a settled coefficient.

**The two penalties compound in the same direction, which is the useful part.**
Co-serving is not a privacy/performance trade where an operator might rationally
choose the risky side for throughput: it is **worse on both axes simultaneously**.
It leaks at the guard layer *and* it runs slower. There is no configuration in
which co-locating two serving personas is the efficient choice.

Scoped honestly: the guard overlap is complete (2/2) while intro points (6+6) and
HSDirs (16+16) stay **disjoint**, so the leak is specifically at the **guard**
layer — which is precisely the layer `ARCHIVAL_FIREWALL_GATE6.md` §10.9 names as
structural, and the layer `ADD_ONION` gives no knob for (SPIKE-F-12).

#### The one question this does *not* answer, carried as SPIKE-F-11

How **one** persona behaves under many *simultaneous readers* is untouched by any
of the above: one persona, one tor, one guard set — fully conformant — with N
clients arriving at once. That is a real TJ-B question (draw rate × shard count ×
organic demand) and it is **unmeasured**. The concurrency arm cannot stand in for
it: it varied two *personas*, not one persona's *readers*.

The earlier ~10-concurrent-readers extrapolation is **withdrawn** — it was fitted
to two points from the co-serving layout and then applied to the reader-concurrency
question, which is a different variable. SPIKE-F-11 needs its own conformant
measurement.

### 12.1 Apparatus validation (done)

The full path — managed tor bootstraps → two personas derived → two loopback
endpoints bound → two `ADD_ONION`s → descriptors published → fetches over real
rendezvous circuits → `DEL_ONION` on shutdown — is green in **41 s**
(`tests/live_apparatus.rs`). Both personas published at the addresses the
derivation predicted, both served their bytes intact over distinct client
circuits, a warm fetch succeeded, and the endpoints' own request counter
confirmed they served what the client leg believed it fetched.

### 12.2 How to produce the numbers

```bash
# 1. Mine a regtest chain past the shard-0 leaf range (~5 h at ~0.69 s/block).
# 2. Extract the real shard.
SHEKYL_SPIKE_RPC=http://127.0.0.1:28601 \
SHEKYL_SPIKE_SHARD_OUT=/path/shard.bin \
  cargo run -p shekyl-sp-t3-spike --release --bin extract-shard

# 3. Run the measurement.
SHEKYL_SPIKE_TOR=/path/to/pinned/tor \
SHEKYL_SPIKE_SHARD=/path/shard.bin \
SHEKYL_SPIKE_OUT=/path/observations.tsv \
SHEKYL_SPIKE_COLD=200 SHEKYL_SPIKE_WARM=200 SHEKYL_SPIKE_CONC=100 \
SHEKYL_SPIKE_HOURS=24 \
  cargo run -p shekyl-sp-t3-spike --release --bin pd-f2-measure
```

### 12.3 Arms and their sample sizes

| Arm | Purpose | `N` run |
|---|---|---|
| Cold circuit, single stream | Pessimistic; circuit build + rendezvous inside the timed path. The faithful model — each drawn miner *is* a different client | **60** |
| Warm circuit, single stream | Optimistic; circuit reused | **60** |
| 2 personas concurrent | §5.2 contention datum | **30 pairs (60 obs)** |
| Soak, ≥ 24 h | Dispersion is time-varying; a one-hour sample understates the tail | **RUN — 2,680 fetches over a full 25 h diurnal span (§13a)** |

**On `N`, and on what more `N` can and cannot buy.** The gate turns on a **10 %
tail**, so the p90 needs a usable confidence interval. At `N = 200` the binomial
standard error on a 0.10 tail probability is `√(0.1·0.9/200) ≈ 0.021` — a
measured `q̂ = 0.10` carries a 95 % CI of roughly `[0.06, 0.14]`, which
**straddles `q_risk* = 0.1011`**. An `N` of 30 — the charter's example — would
not characterise a decile at all.

**Following that arithmetic through changes what the soak is for.** The soak
paces a cold fetch every ~30 s plus the fetch itself, so 24 h yields on the order
of 1 000–1 400 observations. At `N = 1 200` the standard error is `≈ 0.0087` and
the CI is about `[0.083, 0.117]` — **still straddling 0.1011.** No single-vantage
run of feasible length resolves `q` to the third decimal place.

That is not a defect in the plan; it is the reason the deliverable is `D*` rather
than `q̂`. **`D*` does not require resolving `q` at 0.1011** — it requires the
*latency distribution* characterised well enough to locate where `q` crosses
~0.10, which is a question about the shape of the tail, not about the third
decimal of a single probability. So:

- **What more `N` buys:** a tighter estimate of the tail's *location*.
- **What more `N` does not buy:** a verdict of the form "`q` is 0.1011 ± ε".
- **What the ≥ 24 h duration buys, and nothing else can:** coverage of **diurnal
  variation**. §8.3 names circuit-latency *dispersion* as the load-bearing
  parameter, and dispersion is a time-varying quantity — a thousand samples drawn
  in one hour describe that hour, not the day. The soak's value is *span*, not
  count.

Any verdict that does depend on the third decimal place of `q` is outside what
this instrument can deliver, and should be rejected on that basis rather than
supported by a longer run.

### 12.4 The inversion (what gets reported)

Not a pass rate against `CHALLENGE_RESOLUTION_BLOCKS = 10_000` — that constant is
the **pre-TJ** value and §8.3 says explicitly that TJ-C's deadline is a
dependency, not this round's answer. Measuring against it would return a trivial
"not forceable" (10 000 blocks is over a week; every fetch passes) and answer
nothing.

Instead:

> for deadline `D`, the failure probability is `q(D)`;
> `q(D) ≥ q_risk*` holds for all `D ≤ D*`.

`D*` is the deliverable: **TJ-C's deadline must be at or below `D*` for the
sampling branch to remain live.** Three outcomes are distinguished by type:

- `D* = At(d)` — slow fetches push `q` over the threshold at deadline `d`.
- `D* = Unbounded` — the **outright-failure rate alone** already reaches
  `q_risk*`; no deadline, however generous, makes the branch safe. Categorically
  different from a large finite `D*`, and reported as such rather than as a big
  number.
- `D* = Undefined` — empty sample. Reported rather than silently read as zero.

`q_risk*` is carried at full precision (`0.1011`), not rounded to `0.10`: a test
pins that `q = 0.10` is **not** `≥ 0.1011`, because rounding there would
overstate how generous TJ-C's deadline could be — in the worked fixture, by 5×.

---

## 13. §6.5 — which branch the data selects

§8.3's two outcomes are different rounds:

- **Forceable** ⇒ sampling-plus-priced-deadline is live; TJ-A weighs the fork.
- **Not forceable** ⇒ receipt-attested transfer is the only branch, and §8.2 is
  the whole scope.

### The data selects **NOT FORCEABLE**

`D* = 28.57 s` **from the conformant cold single-persona arm** (§12.0b), and the
**smallest deadline a block-granular rule can express is one block = 120 s**.
Every expressible deadline sits on the flat part of the curve where `q = 0.0167`,
six times below `q_risk* = 0.1011`. There is no block-denominated deadline that
forces the threshold, and this is not a near miss: `D*` is **4.2 × smaller** than
the finest available granularity, and no fetch in the arm took even 40 s.

The verdict rests on the **single-persona arms only**. Excluding the
non-conformant concurrency arm *lowers* the governing `D*` (44.00 s → 28.57 s),
so the conclusion holds **a fortiori** — a §10.9-conformant deployment has more
isolation and less shared-process contention than the layout that produced the
larger number.

**Corroborated across the full diurnal cycle (§13a):** the ≥ 24 h soak — 2,680
fetches, four vantages, every UTC hour — puts whole-span `D* = 25.0 s` with **no
hour worse than `D* = 32.5 s`**, all NOT FORCEABLE by ≥ 3.7×. The single-window
caveat the cold arm's `D*` carried is now removed by measurement, not argument.

**Consequence: receipt-attested transfer is the only branch, and §8.2 is the
whole scope.** TJ-A's sampling candidate does not come back to life on this
measurement — which is the same direction §5.6's ROI ledger already reached
independently, now with a transport measurement rather than a cost argument
behind it.

### The one way this conclusion could flip, stated precisely

The measurement is single-vantage (§11), and the bias direction **matters here
and is unfavourable to the conclusion**: a slower miner population raises `q` at
every `D`, which raises `D*`. So `D* = 28.57 s` is a *lower* estimate of the
population's `D*`, not an upper one.

Quantified: for `q(120 s) ≥ 0.1011`, **more than one fetch in ten would have to
exceed 120 s.** In this arm, *zero* did — the slowest success was 39.27 s, so the
population's tail would need to stretch by roughly 3–4 × beyond anything observed
here. That is not absurd for miners on poor links, but it is a large, specific,
and *testable* gap rather than a hand-wave.

**The honest verdict:** not forceable from a well-connected vantage, by a wide
margin, with the single named condition that would overturn it — a
population-level p90 near 120 s — and the multiplier that condition requires.

### 13a. The ≥ 24 h soak — RUN, and it confirms the verdict across the full diurnal cycle

The soak §12.3 named as the right instrument (and §13 called the residual) is
**done**: one conformant persona serving the real shard, sampled by four seed
nodes in four regions, **one fresh-circuit fetch every 120 s per host for 25 h** —
**2,680 fetches, 99.8 % completion, zero tor-heal events**.

```text
WHOLE SPAN (n = 2,680; 2,675 ok, 5 truncated = 0.0019, apparatus-class not timeout)
  p50 10.9 s   p75 16.6 s   p90 24.9 s   p95 29.0 s   p99 60.6 s
  D* = 25.0 s        q(120 s) = 0.0034
  dispersion: min 3.0 s   p50 10.9 s   max 277.3 s     spread = 93×
```

**NOT FORCEABLE holds across every hour of the day.** Bucketed by UTC hour (24
buckets, ~110 fetches each):

- `D*` wobbles **18.6 s – 32.5 s** across the diurnal cycle — a ~1.75× swing, the
  time-variation §8.3 named as load-bearing, now **bounded** rather than feared.
- The **worst hour** (utc20, US-evening peak) is `D* = 32.5 s`, `q(120 s) =
  0.0198` — still **3.7× below** the 120 s block boundary and far under
  `q_risk* = 0.1011`.
- **No hour** comes within a factor of 3 of forcing.

So the diurnal variation the soak exists to catch is real but **small relative to
the 4.8× whole-span margin** (`D* = 25.0 s` vs 120 s). Spanning the daily cycle
did exactly what §12.3 predicted: it did not overturn the verdict, it **removed
the single-window caveat** the earlier `D*` carried.

**SPIKE-F-16 confirmed at scale.** The 93× dispersion (up from the concurrency
run's 30× — a longer window catches more tail) on the identical request is the
same circuit-lottery signature, and the per-hour `D*` wobble *is* that lottery
being time-varying. Per-host medians span 7.8 s – 16.1 s (vantage moves the
median), yet every host stays NOT FORCEABLE.

**The `D*` is no longer quiescent-caveated by the single-window limit** — it spans
the diurnal cycle. (It remains measured with PoW disabled, §17; SPIKE-F-18 shows
that is the zero-cost quiescent state, and SPIKE-F-17 bounds the escalated case.)

### What would settle the residual, and what would not

- **Would settle it:** the same harness run from several *deliberately
  disadvantaged* vantage points (constrained bandwidth, high-latency AS,
  bridge/pluggable transport). That attacks the actual uncertainty.
- **Would not settle it:** more samples from *this* vantage. §12.3's arithmetic
  applies — at any feasible `N` the CI on a 0.10 tail still straddles 0.1011, and
  in any case the question is no longer where `q` sits at 28 s but whether a
  different population has a 10 % tail past 120 s. **More `N` here cannot answer
  that.**
- **The ≥ 24 h soak** — **now carried (§13a)** — confirmed exactly this: diurnal
  variation is real (`D*` 18.6–32.5 s across the day) but small against the margin,
  and no hour comes within 3× of forcing. It was a confirmation, not the pivot, as
  predicted.

---

## 14. What in this branch is disposable, and what may survive

> **Apparatus conformance (read before reusing the harness).**
> `Apparatus::bring_up` takes a `persona_count` and publishes that many onions
> **behind one tor daemon**. For `persona_count > 1` that is a **co-activation
> layout the firewall forbids** (`ARCHIVAL_BOND_CONSTRUCTION.md:667`), and any
> number it produces is an artifact — this is how the first revision's SPIKE-F-1
> and SPIKE-F-10 went wrong. **The conformant configuration is
> `persona_count = 1`**, which is what `D*` is derived from.
>
> **Do not "fix" this by splitting tor instances.** `P` and the principal sharing
> one guard set is the **deliberate §7 residual**, accepted at
> `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md:616` under a heading reading *"correct as-is
> — do not 'fix'"*, because separate instances are **worse**: a non-default config
> is itself a fingerprint to a guard observer — a weaker adversary than the
> correlator the shared guard exposes. One tor process is the correct shape
> (§2a).


**Disposable — everything in `shekyl-sp-t3-spike`.** The crate's first doc
paragraph says so, its name says so, and its route says so (`x-spike/v0`,
deliberately un-shippable). §9.4's freeze consequence is that TJ-B's *response
semantics* become consensus-critical and freeze at genesis; nothing here may be
mistaken for that format. A reviewer who finds `x-spike/v0` cited in a design doc
should treat it as a bug.

> **Amendment (2026-08-11, PR-A of the §9.5 item-3 arc).** The spike's own
> `serve.rs` is **deleted**. The production serving loop landed as
> `shekyl-p-serve`, and the spike now drives it behind a fixture
> `ShardProvider` instead of carrying a near-identical second copy — the two
> had already diverged (accept-error backoff on one side only), which for a
> measurement rig means measuring something other than what ships. The route
> a re-run exercises is therefore `x-provisional/v0`, disclaimed in the same
> terms and with the same standing in the format round: none. Everything this
> section says about the spike's *disposability* is unchanged; what changed is
> that the inbound-hardening shape it validated now has exactly one
> implementation. The numbers already recorded in this document were taken on
> the `x-spike/v0` route and are not restated.

**Candidates to survive, having been *validated* here rather than designed here:**

- **`shekyl_tor::control::onion`** (D1) — already production-shaped and living
  outside the spike crate. Typed arguments, `Detach` unrepresentable, `DEL_ONION`
  on the teardown path before the child is killed, redacting `Debug` on both the
  key and the service id.
- **`PTorClient::blocking_get`** (D5) — the read-side twin of `blocking_post`,
  sharing the one agent so §2b invariant 1 holds.
- **The D2 *construction*** — seed-derived, `p_slot`-bound, nothing at rest — but
  **not its location**; see SPIKE-F-4's reopen criteria.
- **The inbound hardening shape in `serve.rs`** — decoupled accept, per-step
  timeouts, pre-allocation request bound, one route, no logs, identical headers.
  This is transport plan §6a's requirement list made concrete and tested; TJ-B's
  real endpoint should inherit the *shape*, not the bytes.

> **Disposition change (2026-08-04, cross-team request).** The relay team asked
> that the **apparatus be left in place** — it is the shape the owed **Tor
> hop-latency measurement** needs (now on the critical path for the embargo's
> per-zone derivation), and building it twice would be waste. So the rig
> (`serve-only`, the remote-reader harness, the pinned-tor deployment pattern,
> the derived-onion-key + loopback-serve mechanisms) is **retained, not deleted
> at teardown** — its rule-15 disposition moves from "disposable debt" to
> "retained pending a named second consumer." **Reopen-to-delete criterion:** the
> hop-latency measurement lands its own harness, or the embargo work drops the
> dependency.
>
> **Precision on what actually transfers for hop-latency.** This rig times an
> *end-to-end 3.33 MB shard fetch* (rendezvous + transfer), which is **not**
> per-hop or circuit-build RTT. The reusable core for *client-side circuit RTT*
> is more the **control-port / `CircId` machinery already in `shekyl-tor`** (the
> DQ-T0.4 `STREAM`-event + attach-time CircID path) than the serve/fetch harness —
> circuit-build timing is read from control-port `CIRC` events, not from a payload
> transfer. Point the rig's *deployment shell* at that observable rather than
> reusing the fetch loop.

---

## 14a. SPIKE-F-9 — `.gitignore` silently untracks Cargo's `src/bin/`

`.gitignore:88` carries a bare **`bin/`** rule. A bare directory pattern in
gitignore matches a directory of that name **at any depth**, so it matches
`rust/<any-crate>/src/bin/` — Cargo's *conventional* location for a crate's
binaries.

**The failure mode is the bad kind: silent and late.** The binaries build and run
locally, `cargo test` passes, `cargo clippy` passes, and nothing warns. They are
simply absent from the commit. This spike's two binaries were caught only by CI,
whose `cargo fmt --all -- --check` failed with:

```text
Error: file `…/rust/shekyl-sp-t3-spike/src/bin/extract_shard.rs` does not exist
Error: file `…/rust/shekyl-sp-t3-spike/src/bin/pd_f2_measure.rs` does not exist
```

— i.e. `Cargo.toml` referenced files the repository did not contain. Had the
crate declared its binaries by convention rather than with explicit `[[bin]]`
paths, there would have been no `Cargo.toml` reference to dangle and **CI would
have passed with the binaries missing.**

**Worked around here, not fixed.** The spike's binaries live in `bins/` (not
`src/bin/`), with a comment in `Cargo.toml` explaining why they must not be
"tidied" back. That is a local dodge.

**The repo-wide fix is a `.gitignore` change and is out of this charter's file
list**, so it is reported rather than made. The rule presumably targets build
output directories; the candidates are anchoring it (`/bin/`, or the specific
build paths it means) or adding a negation for `src/bin/`. Any Rust crate added
in future that follows Cargo's convention hits this, and the next person may not
have an explicit `[[bin]]` path to make CI notice.

---

## 16. SPIKE-F-14 — the aggregate-load gap, and the two levers built for it

### The gap

`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §6a pins three inbound protections, and
every one is **per connection**: a timeout bounds how long *one* connection
lives, the payload cap bounds *one* request's memory, and spawn-per-connection
**creates** unbounded concurrency rather than limiting it. **Nothing bounds
aggregate load.**

The onion's own stream cap does not either: `MaxStreams` /
`MaxStreamsCloseCircuit` is **per rendezvous circuit**, so `N` distinct clients
get `N` circuits with one stream each and never approach it. It stops one client
hogging; it does nothing about `N` clients.

That matters because of the asymmetry: **a ~100-byte request is answered with
~3.33 MB — roughly 33 000× egress amplification** — and the requester pays only
its own circuit.

**This is a general defect, not a Foundation carve-out.** Unbounded
spawn-per-connection is wrong for **every** `P`: any persona can be handed more
concurrent readers than it can serve, and §6a's per-connection bounds do not
notice. The fix therefore replaces the accept path **in one place**, for all
personas, rather than adding a special mode.

What *is* Foundation-specific is the **load profile, not the mechanism** — and
that distinction is the whole point:

| | Bonded `P` | Foundation complete-tree `P` |
|---|---|---|
| Shard set | bonded subset; cold shards exist | **complete tree — no shard is cold** |
| Requester friction | economic | **none — uncompensated** |
| Reader count | bounded by the challenge draw | **not bounded by any schedule** |

**One mechanism, one defense surface, sized once — against the worst profile and
applied to all.** The Foundation deployment is the *measurement target* for where
the PoW rate/burst floor and the in-flight cap land; it is not a separate code
path, and it must not become one.

### One serving path, and non-anonymous serving stays unrepresentable

All shard retrieval — every persona's, the Foundation's included — occurs over a
**v3 rendezvous**. "Known" describes a persona's **published `.onion` address**,
never a clearnet endpoint. `ADD_ONION`'s `NonAnonymous` flag is therefore **absent
from [`OnionFlags`]**, not merely unset: there is no two-type split and no
single-hop mode to configure, because the type cannot express one. That is
simpler than gating a capability, and it is the same posture as `Detach`.

*(`docs/V3_STAKER_ARCHIVAL.md` previously described a clearnet fetch leg for the
Foundation seeds; corrected 2026-08-03 — see that file's correction note.)*

### Lever 1 — onion-service PoW (`shekyl_tor::control::onion::OnionPow`)

tor ships a defense for exactly this, and it was missing from the D1 type.
`ADD_ONION` takes `PoWDefensesEnabled` / `PoWQueueRate` / `PoWQueueBurst`
(control-spec; defaults **0 / 250 per second / 2500**), which throttle the
**rendezvous-request priority queue** — i.e. **arrival**, not egress.

Typed as a three-state enum so invalid combinations are unrepresentable:
`Disabled` (tor's default, and correct for a bonded persona), `Enabled` (renders
the switch only, leaving 250/2500 as **tor's** numbers to own and version rather
than a stale copy here), and `EnabledTuned { queue_rate, queue_burst }` for a
deployment that has *measured* its load.

**Verified against real tor, not just KAT'd.** The live round-trip publishes a
service with `EnabledTuned` and asserts `250` — the same discipline that caught
`MaxStreamsCloseCircuit` being a `Flag` rather than an argument. Grammar position
(Flags → MaxStreams → PoW\* → Port) is pinned by ordinal assertion, because tor
answers an out-of-order argument with a `512`.

### Lever 2 — bounded in-flight connections (`MAX_INFLIGHT`)

PoW bounds arrival; it does not bound how many accepted connections are streaming
at once. A semaphore caps concurrency, and an arrival past the cap is **closed
immediately** rather than queued.

**The refusal is a close, deliberately not a `503`.** A new status code would add
a response shape to the provisional surface that §9.4 warns must never be
mistaken for TJ-B's, and would hand a prober a free capacity oracle. A closed
connection is indistinguishable from ordinary circuit failure — which, over Tor,
is what a client already handles. `refused_count()` is the aggregate operator
signal, with no log and no per-request structure.

Tested with a **negative control**: one test asserts the cap sheds load *and*
that refusals carry no status line; the other asserts the cap does **not** fire
below it, so a broken-always-refuse implementation cannot pass.

### What is still owed

`MAX_INFLIGHT` is **`SPIKE-PIN-2` — a placeholder, not a derivation.** The binding
resource is *egress*, not memory (the payload is one shared `Arc`, so concurrency
costs descriptors and tasks, not `N × 3.33 MB`). Deriving it, and sizing PoW's
queue parameters, is **SPIKE-F-11 measured on the hardware that will actually
serve** — which is why F-11 is re-rated for the Foundation deployment: there it is
not a tail case, it is the operating condition, and the reader count is
adversarially inflatable.

---

## 18. SPIKE-F-11 — ANSWERED: reader concurrency is not the variable that matters

### Method

Four **real remote hosts** (`skl-seedaus`, `skl-seedeu`, `skl-seeduse`,
`skl-seedusw` — four regions), each running the **hash-pinned Tor Expert Bundle**
(sha256 verified against `CURRENT_PIN` on all four before the run), fetching the
**real 3 326 976-byte shard** from **one conformant persona**
(`persona_count = 1`) over live Tor.

Every fetch used a **unique SOCKS proxy-user**, so each got its own circuit and
its own rendezvous carrying one stream — the faithful model (`N` drawn miners
*are* `N` clients) and the reason the per-circuit `MaxStreams` cap never binds
(`SPIKE-PIN-1`'s recorded trap).

This is the confound `pd-f2-measure` could not escape: there, client and server
share one host, so at concurrency the box is measured rather than the persona.
Here the readers are elsewhere.

### Result — 180 fetches

| readers | `n` | completion | p50 | p75 | p90 | `>20 s` | `>120 s` | `D*` | `q(120 s)` |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 12 | 1.000 | 10.92 s | 13.32 s | 14.07 s | 0.083 | 0.000 | 13.39 s | 0.0000 |
| 8 | 24 | 1.000 | 11.45 s | 24.93 s | 109.50 s | 0.333 | 0.042 | 70.80 s | 0.0417 |
| 16 | 48 | 0.958 | 11.43 s | 16.39 s | 24.89 s | 0.188 | 0.042 | 26.39 s | 0.0417 |
| 32 | 96 | 0.990 | 14.83 s | 21.79 s | 33.03 s | 0.260 | 0.021 | 33.03 s | 0.0208 |

**`q(120 s)` never exceeds 0.0417 at any `N`** — always well below
`q_risk* = 0.1011`. **NOT FORCEABLE holds across the entire sweep**, and the
worst point is the *least* loaded one.

**`MAX_INFLIGHT` never bound: `refused = 0` at every `N`.** So `SPIKE-PIN-2` was
not the limiting factor at ≤ 32 readers, and sizing it requires load well beyond
what this rig produced. The cap remains a placeholder, now with a measured lower
bound on where it *isn't* binding.

### The answer, and it is not the one the question expected

**Reader concurrency is not the variable that matters.** An 8× increase in
readers moved the median from 10.92 s to 14.83 s (+36 %) and *reduced* the
outright-failure share. Completion stayed ≥ 95.8 %.

Meanwhile `D*` went **13.39 → 70.80 → 26.39 → 33.03 s** — **non-monotonic**. More
load produced a *smaller* `D*`. That is not noise to be sampled away; it is
SPIKE-F-16.

## SPIKE-F-16 — circuit dispersion dominates, and it is §8.3's own named parameter

Pooling all 177 successful fetches of the **identical** request to the **same**
persona:

```text
min 4.49 s   p50 13.36 s   max 133.05 s        spread = 30x
per-region p50:  seed-use 11.40   SeedEU 13.31   seedaus 13.87   seedusw 14.07
```

**A 30× spread on an identical request, with regional medians agreeing within
2.7 s.** The variance is not geography, not the service, and not reader load — it
is *which relays the circuit drew*. Over Tor the path is three relays plus a
rendezvous: **someone else's connection, unknown and unpredictable.**

That is exactly what §8.3 named — *"circuit-latency dispersion as the load-bearing
parameter"* — now demonstrated rather than asserted.

**Three independent apparatus agree on the median and disagree on the tail:**

| apparatus | median total |
|---|---|
| `c76cc6ad8` (parallel thread, PoW rig) | 13.3 s |
| this spike, single-host cold arm | 14.71 s |
| this spike, distributed 4-region | 13.36 s |

**The median is reproducible; the tail is a lottery.** Since `D*` *is* a tail
statistic, `D*` inherits that instability — which has a direct methodological
consequence:

> **More concurrency does not characterise the tail. More independent circuit
> draws over time does.** The ≥ 24 h soak is therefore the right instrument for
> `D*`, and this sweep is the wrong one — it varies the parameter that does not
> matter while holding fixed the one that does.

### Honest limits

- **Percentiles above p90 are not meaningful here.** At `n = 12…96`, the reported
  "p99" is at or near the **maximum observation**, not a 99th percentile.
- **Environment, measured not assumed:** the service host's egress was measured at
  **60.3 Mb/s** (50 MB over ssh to a seed, interface counters sampled). An earlier
  draft of this section cited 10 Mb/s from `/sys/class/net/<if>/speed`; that file
  reports the NIC's negotiated link, is unreliable for USB adapters, and was
  **wrong by 6×**. At ~2.4 Mb/s per fetch the measured figure supports ~25
  concurrent, so **only the 32-reader point is near the host's egress** and should
  be treated as the least trustworthy row.
- Four vantage points, one service host, one time window. Per §11, this does not
  generalise to a globally distributed miner population — and SPIKE-F-16 is
  precisely why it cannot.

### What this does not answer

The **client give-up ceiling** (§17). `c76cc6ad8` reached effort 67 without its
client hitting the ceiling; the spec's client bound is 10 000. That measurement
needs *sustained escalation*, which needs `QueueRate` tuned as a sensitivity trick
(ambient load is ~3 intros/epoch, nowhere near tor's stock 250/s). The rig built
here supports it — `serve-only` takes `SHEKYL_SPIKE_POW=tuned:<rate>:<burst>` —
but it is a separate run.

---

## 19. SPIKE-F-17 — the ceiling is a clamp, which bounds SPIKE-F-15

`c76cc6ad8` left "the client give-up ceiling" as the real pin input, and §17
carried it as the regime where PoW could move `D*` materially. **Reading the
pinned binary changes that framing**, and in the reassuring direction.

### PoW is genuinely compiled in (a caveat now closed)

§17 flagged that tor *accepting* the PoW arguments is not proof the defense is
built. Verified on the pinned Expert Bundle 15.0.17:

```text
$ tor --list-torrc-options | grep -i pow
HiddenServicePoWDefensesEnabled
HiddenServicePoWQueueBurst
HiddenServicePoWQueueRate
```

and the binary carries the implementation's own strings (`pow-params`,
`Recalculated suggested effort: %u`, `tor_hs_pow_suggested_effort`). The caveat is
discharged.

### The ceiling is a clamp, and the client does not give up

The client-side string is:

> `Onion service suggested effort %d which is higher than we want to solve.`
> `Solving at %d instead.`

**The client clamps to its own maximum and still solves.** It does not abandon the
fetch. And there is **no client torrc knob** for that maximum — the only
PoW-related client option is `CompiledProofOfWorkHash` (which implementation to
use, not how much effort to spend), so the bound is a **compile-time constant**,
not operator-tunable.

**Consequence for SPIKE-F-15.** §17's concern was that escalation drives honest
miners' solve cost up without limit, shifting `D*` toward the deadline. That is
**bounded**: however high a service escalates its `suggested_effort`, an honest
client pays at most *solve-at-clamp*, a fixed quantity. The coupling between the
DoS defense and the §8.3 margin is therefore **real but capped**, and the cap is a
property of the client binary rather than of the attack.

What remains genuinely unmeasured is the **value** of that constant and the solve
time at it. Per `hspow-spec` the client bound is **10 000**; `c76cc6ad8` measured
solve at effort 67 as median 0.19 s. Naive linearity would put solve-at-10 000
near ~28 s — **but that is exactly the kind of unjustified extrapolation this
report withdrew once already (§12.0d), and it is not asserted here.** It is
directly measurable without any escalation rig, by solving at a fixed effort, and
that is the right way to close it.

### Method findings from the escalation attempt (which did not escalate)

An escalation run was attempted — service on the dev box with
`PoW tuned:1:1`, four seed nodes flooding — and **failed to raise
`suggested_effort` off 0**. Three things were learned that the next attempt needs:

- **Bandwidth pressure is not queue pressure.** Flooding with full 3.33 MB fetches
  drove a measurement fetch from 9.5 s to **109 s** — real congestion — with
  **zero** escalation. The AIMD controller reacts to *rendezvous arrival rate*,
  not bytes. Re-pointing the flood at a 404 path (full rendezvous, tiny response)
  raised churn but still did not escalate within the run.
- **`pow-params` is unreadable from the control port.** It lives in the
  descriptor's **superencrypted** layer, so `GETINFO hs/service/desc/id/<addr>`
  cannot show the service's current effort. An effort-watcher built on that
  returned nothing, correctly.
- **The right instrument is `MetricsPort`.** The binary exports
  `tor_hs_pow_suggested_effort`. Reading that is a direct, unencrypted,
  service-side observable — and unlike the descriptor it needs no decryption and
  no fresh-client dance. Note that `ManagedTor`'s spawn surface is six typed
  options with **no** `MetricsPort` knob, so wiring this is a typed-knob addition
  (`actor.rs`), not a config change.

**Disposition:** SPIKE-F-15's coupling is bounded by SPIKE-F-17. The residual —
solve-time at the client clamp — is a small, self-contained measurement that needs
no flood, no seeds, and no escalation. It should be done that way rather than by
rebuilding the escalation rig.

## 19a. SPIKE-F-18 — enabling PoW costs a quiescent persona nothing

A second escalation attempt (six hosts — four seeds + two 8-core miners — 160
concurrent rendezvous attempts, against **both** an `ADD_ONION` service and a
**native-torrc** service with `HiddenServicePoWQueueRate 1`) again **did not raise
`suggested_effort` off 0**. But it produced a cleaner, decisive observation.

**An idle client fetching the PoW-enabled service sees no `pow-params` at all.** A
fresh client with tor at `info` verbosity fetched the native service in 5.7 s
(HTTP 200) and logged **none** of the implementation's PoW strings — no `PoW
params present in descriptor`, no solve. This is not a failure; it is the
mechanism working as `hspow-spec` describes:

> *"The service starts with a default suggested-effort value of 0, which keeps the
> PoW defenses **dormant** until we notice signs of queue overload."*

At effort 0 the descriptor carries **no `pow-params`**, so clients have nothing to
solve. PoW is *armed*, not *active*.

**Operational consequence, and it is favourable for the Foundation `P`.** Turning
PoW on is **free in quiescence**: a persona that enables it pays nothing, its
clients pay nothing, and it advertises nothing extra — the defense materialises
*only* under genuine rendezvous-queue overload, and recedes again after. So PoW is
a correct default to ship **enabled** on the uncompensated complete-tree persona
(§16): no steady-state cost, protection exactly when attacked.

### Why escalation did not reproduce (recorded so the next attempt does not repeat it)

The rig was not the bottleneck: **client tor sat at < 2 % CPU, load 0.00**, so this
was not the flood saturating the client side. The signature was 100 %
client-side timeouts (`http_000`) at a 25 s bound. The most consistent reading is
the interaction between `QueueRate 1` (the service dispatches one rendezvous per
second) and the client timeout: at ~160 arrivals against 1/s service, all but the
first few queue past 25 s and the clients **disconnect**, cancelling their queued
requests faster than the AIMD's overload condition persists at the verbosity
available. `c76cc6ad8` *did* reach effort 67/128 from four seeds, so escalation is
achievable — the difference is almost certainly that its flood requests **completed**
(short successful rendezvous that churn the queue) rather than timing out. A future
escalation rig should use a **completing** load with a longer client timeout, and
observe effort through **`MetricsPort`** (`tor_hs_pow_suggested_effort`) rather than
the superencrypted descriptor or the notice-level log — both of which this run
confirmed cannot show it (§19).

**This does not change any disposition.** SPIKE-F-17 bounds the honest-client cost
from source regardless of achievable effort; SPIKE-F-18 shows the quiescent cost is
zero; and the one residual (solve-time at the clamp) is measured by solving at a
fixed effort, not by a flood.

---

## 20. SPIKE-F-19 — the fixed payload size is a guard→persona confirmation oracle (TJ-B)

**Recorded here, decided in TJ-B.** This is a wire-format property, and §9.4
freezes the response format at genesis — so it is decided *once*, and adding the
mitigation later is not a patch. It is written down now because it is exactly the
kind of finding that gets rediscovered expensively after the format has frozen.

### The correction to this report's own earlier reassurance

This report's earlier guard-threat framing (SPIKE-F-1's original threat tuple, and
the PR's guard-coupling note) held that a guard learns co-residency but **not**
which `.onion` addresses it carries — that binding an address to an IP is the
standard hidden-service location-discovery problem *"Tor's guard design exists to
make expensive."* **That reassurance is too optimistic for a *serving* persona,
and in the direction this report has repeatedly had to correct** (underestimating
the adversary). The serving design makes the binding cheap, not expensive.

### What a guard actually sees, and it is not circuit contents

Circuit *contents* are encrypted end to end; the guard never sees them, and Tor
never claimed to hide circuit-level *metadata*. Two results on that metadata:

- **Passive.** Kwon et al. (USENIX Security '15, *Circuit Fingerprinting
  Attacks*) showed an entry guard can classify hidden-service circuits from cell
  sequences, direction, timing, and duration at **> 98 % TPR / < 0.1 % FPR**, and
  the classifier also tells the adversary *which side it is on* (client-of-HS vs
  HS). A cruder tell needs no classifier: an intro-point circuit is a long-lived
  connection on which the OP sends only **3 cells at the very beginning** —
  structurally distinctive because of what intro circuits are for. Follow-up work
  extended the attack to a **middle relay (~99.98 %)**, which needs *fewer*
  resources than earning the guard flag.
- **Active — the part that matters for Shekyl.** Classification says "I carry a
  hidden service," not *which one*. Linking a guard to a specific `.onion`
  normally needs a confirmation step: force the service to build a rendezvous to
  an adversary-controlled RP, inject a traffic signature, recognise it at the
  colluding relay.

**The serving design makes that step nearly free.** The `.onion` is public by
necessity, the fetch is uncompensated, and the payload is **exactly 3,326,976
bytes**. A guard-holding adversary fetches a shard at a moment of its choosing and
looks for the matching flow — **no padding signature to construct, because the
shard *is* the signature**: large, fixed-size, requestable on demand. Repeat
twice and the false-positive rate collapses.

### Throttling needs even less than deanonymization

The papers above aim to *deanonymize* — learn *where* the service is. A
**throttling** adversary needs only to know *which circuit to slow*; location is
irrelevant. So the oracle feeds SPIKE-F-14's targeted-DoS surface even against a
persona whose location is already public (the Foundation `P`), where
deanonymization reveals nothing new.

### Economics — why the probe amortises

Guards are held for months (Tor's own framing: *"one fast guard for life, or 9
months"*), so the confirmation is **one-time per persona and amortises across the
guard's whole lifetime**. A guard slot covers whatever personas draw it, and the
operator enumerates them cheaply because **every `P` is publicly fetchable**.

### Where this is tempered (the honest bound, stated with the finding)

These are **research accuracies under controlled conditions**; open-world base
rates degrade them, and Tor has shipped padding changes since 2015 that the 2015
results do not account for. The per-draw probability of an adversary landing on
any *specific* persona's guard is small. So the claim is **not** "guards know
which persona this is" — it is *"a guard operator who cares can find out cheaply,
and the fixed payload shape makes it cheaper than the literature assumes."*

### The one design lever, and why it cannot wait

Variable-length responses (padding the shard to a distribution of sizes) blunt the
active confirmation, at a bandwidth cost. **That trade is TJ-B's**, and it
**must** be taken inside the frozen response format if taken at all: padding is a
wire-format property, so a TJ-B that lands without it cannot add it later without
a consensus-boundary change. Recorded against §9.4's freeze consequence and as
open item **TJ-H** so whoever specifies the format meets it there.

---

## 15. Pins recorded for later derivation

- **`SPIKE-PIN-1` — `MaxStreams=8`.** Chosen conservatively, not measured. A shard
  read is one stream per connection and the harness never opens more; 8 leaves
  headroom without letting one client hold many streams on a rendezvous circuit.
  Derive properly from the concurrency TJ-B's draw actually produces.

  **Precondition for SPIKE-F-11 — the pin can corrupt that measurement if the arm
  is built wrong.** `MaxStreams` is **per rendezvous circuit**, not per service
  (control-spec: *"the maximum streams that can be attached on a rendezvous
  circuit"*), and it is paired with `MaxStreamsCloseCircuit`, which **closes the
  circuit** rather than refusing the extra stream. So:
  - **`N` readers must be `N` distinct client ids.** Distinct SOCKS usernames ⇒
    distinct circuits ⇒ distinct rendezvous ⇒ one stream each, and the pin never
    binds. This is also the faithful model — `N` drawn miners *are* `N` clients.
  - **Fanning `N` requests out from one client id is the trap.** They share a
    circuit, so at `N > 8` the pin closes it, and the run records circuit failures
    that look like network behaviour but are the harness measuring **its own
    pin**. A tail that appears past `N = 8` is the first thing to suspect.

---

## 21. Cross-domain transfers to the relay layer (flagged by another team, 2026-08-04)

Two of this spike's findings were flagged as transferable to the Dandelion++ /
relay-privacy work. **Provenance:** the transfers and their ordering consequences
are the relay team's reasoning (read from commit messages + the design doc, not
the full measurement reports); the *measurement calibration* below is mine, from
the runs. The design-side ordering calls (e.g. whether §30's composition moves
nearer the stem work) are **theirs to make with their context — not ruled here.**

### 21.1 SPIKE-F-1 breaks an independence assumption D++-over-Tor would rest on

**Their reasoning.** Dandelion++ treats the stem successors as *independent*
observation points — that independence is what makes holding one slot worth `f`
rather than more. But if the daemon's P2P rides **one tor process**, every
outbound circuit draws the **same entry-guard set**, so a single entry guard
observes traffic to **all** successors at once: the node's complete
**emission timeline** — every stem send, every fluff, timestamped. Content is
encrypted and post-mixing cannot separate originated from relayed, but the
*timing* is exposed. That is precisely the recall-1 wire observer Q-11's cover
traffic exists to deny — and cover is currently deleted (`noise(false)`). So the
ordering consequence they draw: **D++ over Tor shipped without cover restored
hands the entry guard a full transaction-emission timeline**, undefended, which
argues for §30's composition being nearer the stem work than a later phase.

**My calibration (confirms the substrate, and strengthens it).**
- **The guard-sharing substrate is measured, not assumed.** SPIKE-F-1: two
  personas behind one tor drew a **complete** 2-guard overlap. SPIKE-F-12
  establishes *why* structurally: the guard set is a property of the **tor
  process / `DataDirectory`**, not of the circuit — so it applies to **any**
  circuit that process builds, client stem-sends included, not only the onion
  services I measured. The extension to client circuits is sound by that
  per-process property; I flag it as *inference from a measured mechanism*, not a
  second measurement.
- **It is durable, which sharpens the point.** DQ-T0.7 pins the `DataDirectory`
  **persistent**, so the guard set is **stable across sessions**. The observer is
  therefore not "an entry guard for one session" but a *small, stable set (2 in my
  run) for potentially the node's lifetime* — a lifetime emission timeline to
  whoever holds one of those two slots.
- **One conditional to keep explicit:** this bites **iff** the daemon's D++ P2P
  actually rides a single shared tor process. The measurement establishes the
  consequence *given* that layout; it does not assert the layout.

### 21.2 The independence caution extends to per-peer circuits — as a HYPOTHESIS

**Their reasoning.** "A design that assumes independence between co-hosted
personas under load is unsupported by anything measured here" transfers to
per-peer circuits: if the relay layer anywhere assumes congestion/stalling on one
Tor peer is independent of another, that is unsupported for peers sharing a tor
process — a stall induced on one circuit may not be isolable, which changes what
the linkage adversary can do. Worth checking against **Unit 2's perturbation
model**. They correctly mark this **their hypothesis**, extended from a finding
this report explicitly marks unmeasurable.

**My calibration (the honesty cuts their way, with one thread of support).**
- The specific axis — *deliberate* load on one circuit observably affecting
  another — is the one I marked **UNMEASURABLE-HERE** (§8) and **did not claim
  either way**. Their hypothesis is correctly labelled as such.
- The **one adjacent datum**: SPIKE-F-10 measured that co-serving two personas on
  one tor produced **mutual contention** (`D*` ×1.54). That is weak positive
  evidence that circuits sharing a tor process are **not fully independent under
  load** — but it is *co-served onion services at N=2, one run, C-tor, labelled a
  floor*, **not** the per-peer client-circuit case and **not** the deliberate-stall
  (perturbation) case. So it nudges the hypothesis from "unsupported" toward
  "plausible, one shared-process contention datum," and **no further**. The Unit-2
  perturbation check is the right next step, and it is a measurement, not a
  deduction from this spike.

### 21.3 Apparatus reuse

Recorded in §14's disposition change: the rig is retained for the owed Tor
hop-latency measurement, with the precision that the reusable core for *circuit
RTT* is the control-port/`CircId` machinery, not the shard-fetch loop.

---

## Revision history

- **2026-08-03:** Created. D1–D6 built; halt conditions §8.2 (regtest shard) and
  §8.3 (v3 key encoding) both evaluated and **not** fired; §8.5 (intro-point
  sharing) evaluated and **refuted**. SPIKE-F-1 (shared guards) reported as the
  spike's principal output. PD-F-2 distribution pending.
- **2026-08-03 (same day, post-run):** PD-F-2 measured on a real shard —
  `D* = 28.57 s`, §8.3 answered **NOT FORCEABLE**.
- **2026-08-03 (correction, maintainer-sourced):** the apparatus was found
  **non-conformant** — it put two personas on the wire simultaneously, which
  `ARCHIVAL_BOND_CONSTRUCTION.md:667` forbids, and `ARCHIVAL_FIREWALL_GATE6.md`
  §10.9 (ratified Round-2 exit pin) already required non-overlapping guard sets
  for exactly that reason. **SPIKE-F-1 re-dispositioned REFUTED AS STATED**; its
  "mitigation may be counterproductive" disposition **withdrawn** as an argument
  against a ratified pin sourced from the forbidden configuration.
  **SPIKE-F-10 re-dispositioned as a *deterrence floor*** — a measurement of the
  forbidden layout is what lets the project *price* it, and the price lands on
  **both** axes at once (complete guard overlap **and** ≥ ×1.54 on `D*`), so
  co-serving is never the efficient choice. The ×1.54 is labelled a **floor**
  (C-tor, `N = 2`, one vantage, one run), not a coefficient. The
  reader-concurrency question is separate and carried as **SPIKE-F-11**
  (unmeasured). `D*` **re-derived from the single-persona arms only**; the
  conclusion holds *a fortiori* because the excluded arm was the slowest. The
  data is repurposed as **SPIKE-F-12**.
- **2026-08-03 (third correction, maintainer-sourced):** SPIKE-F-12's routing was
  **wrong** and is removed. `TRANSPORT_PLAN:616` accepts the `P`↔principal guard
  coupling as the deliberate §7 residual and **explicitly forecloses separate
  instances** (a non-default config is a stronger fingerprint than the correlator
  the shared guard exposes); DQ-T0.7 independently records that within-session
  guard sharing is "unaffected either way: same process, same guards." So the
  measurement **corroborates an accepted residual** — no action, **no routing to
  `:1644`** — and every "separate tor processes" recommendation this document
  carried has been purged, since it invited exactly what `:616` was written to
  prevent. The suggested "torrc-surface review" is likewise withdrawn: `actor.rs`
  passes typed options only and deliberately has no free-form config surface.
  New **SPIKE-F-13** records that §10.9's *Arti* mechanism clause (and three
  further sites) is dead text, since the Expert Bundle is the path and the Arti
  anchor never fires — flagged for maintainer ruling, **no ratified text edited
  here**.
