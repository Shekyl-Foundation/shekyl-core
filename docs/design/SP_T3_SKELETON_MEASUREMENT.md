# SP-T3 serving skeleton — the PD-F-2 dispersion measurement

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
   measured what §10.9 predicts. Its data is repurposed to inform the *open*
   §10.9-enforcement carry (§2a).
2. **The former "mitigation may be counterproductive" disposition is
   WITHDRAWN.** It argued against a ratified pin from a measurement of the
   forbidden configuration, and §10.9 had already weighed and ruled on that exact
   trade.
3. **`D*` is re-derived from the single-persona arms only** (§12.0b). The
   concurrency arm is labelled **non-conformant** and excluded from the verdict.
4. **SPIKE-F-10 splits** (§12.0d): the co-hosted-persona contention number is a
   forbidden-layout artifact and is withdrawn; the single-persona reader-
   concurrency question survives as **SPIKE-F-11**.

---

## 0. What this spike found, in one screen

| # | Finding | Severity | Verdict |
|---|---|---|---|
| **SPIKE-F-1** | ~~Two personas behind one tor share entry guards~~ | — | **REFUTED AS STATED** — the apparatus built a co-activation layout §10.9 forbids; not new information (§2) |
| **SPIKE-F-12** | **`ADD_ONION` has no per-service isolation knob, so C-tor with N onions on one daemon cannot satisfy §10.9's non-overlapping guard sets.** §10.9 specifies *Arti*; the enforcement mechanism is an **open rule-21 carry** (`:1644`, routed to the Transport PR) and shekyl-tor is C-tor | **HIGH** | **CONFIRMED (measured)** — the live carried item this spike actually informs (§2a) |
| **SPIKE-F-2** | Two personas' onion services do **not** share introduction points | HIGH (as a *negative*) | **REFUTED (measured)** — halt condition §8.5 does not fire |
| **SPIKE-F-3** | `MaxStreamsCloseCircuit` is a **`Flag`**, not a `MaxStreamsCloseCircuit=1` argument; the argument spelling earns `512` from tor | MEDIUM | **CONFIRMED (measured)** |
| **SPIKE-F-4** | A production persona onion key belongs in `archival_p.rs`, not in a second cSHAKE256 path from the master seed | MEDIUM | **CONFIRMED (source)** |
| **SPIKE-F-5** | `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` claimed SP-T0a delivered `ADD_ONION`/`DEL_ONION`. It did not | LOW | **CONFIRMED (source)** — corrected in this branch |
| **SPIKE-F-6** | The persona descriptor is a **liveness oracle** with ~3 h granularity, and it is an irreducible floor of running an onion service | MEDIUM | **CONFIRMED (measured)** |
| **SPIKE-F-8** | Two personas' descriptors land on **disjoint HSDir sets** (16 each, zero overlap) — the "shared HSDir" axis SP-T2 flagged does not exist | MEDIUM (as a *negative*) | **REFUTED (measured)** |
| **SPIKE-F-9** | `.gitignore`'s bare `bin/` rule silently untracks **any Rust crate's `src/bin/`** — Cargo's conventional binary location | MEDIUM (repo-wide) | **CONFIRMED (CI)** |
| **SPIKE-F-10** | ~~Co-hosted personas contend (×1.54)~~ | — | **WITHDRAWN** — measured under the forbidden co-activation layout; artifact, not architecture (§12.0d) |
| **SPIKE-F-11** | **One** persona facing many simultaneous readers is a genuine, §10.9-unaffected TJ-B question the margin is sensitive to — and it is **unmeasured** | MEDIUM | **OPEN** (§12.0d) |
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

## 2a. SPIKE-F-12 — the finding the data actually supports: **C-tor cannot deliver §10.9**

This is where SPIKE-F-1's measurement belongs, restated against a question that
is genuinely open.

**§10.9's enforcement mechanism is an unresolved rule-21 carry, not a closed
door.** `ARCHIVAL_FIREWALL_GATE6.md:1644`:

> **§10.9 isolation enforcement mechanism** (Arti config vs. policy) + S-6
> key-locality provisioning → **Transport PR** + PHASE_2B engines. *Independent
> guard sets + restore-flow non-co-activation must be **structural**.*

And §10.9 specifies the mechanism as **separate Arti client instances**. This
spike ran **C-tor** — the hash-pinned Tor Expert Bundle driven over the control
port — because that is what `shekyl-tor` is. (`:479` carries the at-source Arti
pin to the transport PR under GF-12; the Arti-vs-C-tor question is live.)

**The measured statement, scoped to what was actually established:**

> With C-tor, **`ADD_ONION` exposes no per-service isolation parameter of any
> kind.** Every onion service published on one tor daemon, and every client
> circuit that daemon builds, draws from that daemon's single guard set. Measured:
> two services on one daemon received *identical* two-guard sets, while their
> introduction points (6+6) and HSDir sets (16+16) were disjoint — so the sharing
> is specifically at the **guard** layer, and specifically **not** at the layers
> tor derives per-service from the blinded key.

**Why that matters to the carry.** §10.9 requires the isolation to be
*structural*. On C-tor there is no config knob that provides it: non-overlapping
guard sets would require **separate tor processes with separate `DataDirectory`
trees** (the guard set lives in the datadir's `state` file — see
`ManagedTor::data_dir`'s DQ-T0.7 note on guard-identity persistence). That is a
material provisioning fact for the transport PR, and it is the thing this spike
is genuinely able to tell it.

`T = ⟨` guard-level observer (C2); sees that one IP's circuits share an entry
relay; cost = run/observe a Guard-flagged relay; priced in transport plan §7 `⟩`
— **as §10.9 already prices it.** The novelty here is not the threat, it is the
**mechanism gap**: C-tor has no knob, so the pin needs process separation.

**Disposition:** hand to the Transport PR as input to the `:1644` carry. This
spike does **not** decide Arti-vs-C-tor and does not reopen §10.9.

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
| ~~Co-hosted personas contend under concurrent load~~ | **WITHDRAWN** | Measured under the forbidden co-activation layout; an artifact of a deployment §10.9 prevents. Superseded by **SPIKE-F-11** (one persona, many readers), which is conformant and **unmeasured**. |
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

### 12.0d SPIKE-F-10 splits: one artifact discarded, one real question carried

The first revision reported "co-hosted personas contend, `D*` ×1.54" as
SPIKE-F-10. That splits into two claims with opposite fates.

**Withdrawn — the contention number is a forbidden-layout artifact.** Two
personas serving simultaneously through one tor is precisely the co-activation
`ARCHIVAL_BOND_CONSTRUCTION.md:667` rules out. Under §10.9 the production shape
has *more* isolation and *less* shared-process contention, so the ×1.54 measures
a deployment that will not exist. It is not evidence about the architecture and
must not be cited as such.

**Carried as SPIKE-F-11 — single-persona reader concurrency is genuinely open.**
How one persona behaves under many *simultaneous readers* is untouched by §10.9:
that is one persona, one tor, one guard set — conformant — with N clients
arriving at once. It is a real TJ-B question (draw rate × shard count × organic
demand), the margin is plausibly sensitive to it, and **this spike did not
measure it.** The concurrency arm cannot stand in for it, because it varied the
wrong thing: two *personas*, not one persona's *readers*.

The former ~10-concurrent-readers extrapolation is **withdrawn with the
artifact** — it was fitted to two points from the forbidden layout, and its
functional form was never justified. SPIKE-F-11 needs its own measurement, on a
conformant single-persona apparatus.

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
| Soak, ≥ 24 h | Dispersion is time-varying; a one-hour sample understates the tail | **not run** — see §13 |

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

### What would settle the residual, and what would not

- **Would settle it:** the same harness run from several *deliberately
  disadvantaged* vantage points (constrained bandwidth, high-latency AS,
  bridge/pluggable transport). That attacks the actual uncertainty.
- **Would not settle it:** more samples from *this* vantage. §12.3's arithmetic
  applies — at any feasible `N` the CI on a 0.10 tail still straddles 0.1011, and
  in any case the question is no longer where `q` sits at 28 s but whether a
  different population has a 10 % tail past 120 s. **More `N` here cannot answer
  that.**
- **The ≥ 24 h soak** remains worth running for the diurnal-dispersion reason
  (§8.3's load-bearing parameter), and is the arm this report does *not* yet
  carry. But note what the cold arm already shows: the gap to the finest
  block-denominated deadline is 4.2 ×, so diurnal variation would have to be
  enormous to close it. **The soak is now a confirmation, not the pivot.**

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
> A harness that legitimately needs two *isolated* network identities on one host
> — `P` vs principal, per §10.9 — must run **separate tor processes with separate
> `DataDirectory` trees**, because the guard set is per-datadir (`ManagedTor::data_dir`,
> DQ-T0.7) and `ADD_ONION` offers no per-service knob (SPIKE-F-12). Building that
> is transport-PR work, not spike work.


**Disposable — everything in `shekyl-sp-t3-spike`.** The crate's first doc
paragraph says so, its name says so, and its route says so (`x-spike/v0`,
deliberately un-shippable). §9.4's freeze consequence is that TJ-B's *response
semantics* become consensus-critical and freeze at genesis; nothing here may be
mistaken for that format. A reviewer who finds `x-spike/v0` cited in a design doc
should treat it as a bug.

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

## 15. Pins recorded for later derivation

- **`SPIKE-PIN-1` — `MaxStreams=8`.** Chosen conservatively, not measured. A shard
  read is one stream per connection and the harness never opens more; 8 leaves
  headroom without letting one client hold many streams on a rendezvous circuit.
  Derive properly from the concurrency TJ-B's draw actually produces.

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
  **SPIKE-F-10 withdrawn** as a forbidden-layout artifact and split, with the
  conformant half carried as **SPIKE-F-11** (one persona, many readers —
  unmeasured). `D*` **re-derived from the single-persona arms only**; the
  conclusion holds *a fortiori* because the excluded arm was the slowest. The
  data is repurposed as **SPIKE-F-12** — C-tor exposes no per-service isolation
  knob, so §10.9's *structural* requirement needs separate tor processes — which
  is input to the **open** `:1644` enforcement-mechanism carry (Arti vs. policy),
  routed to the Transport PR. This spike does not decide Arti-vs-C-tor and does
  not reopen §10.9.
