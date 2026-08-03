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

## 0. What this spike found, in one screen

| # | Finding | Severity | Verdict |
|---|---|---|---|
| **SPIKE-F-1** | Two personas behind one tor **share entry guards**; `ADD_ONION` has no per-service isolation knob, so the inbound axis has no analogue of SP-T1's SOCKS-username isolation | **HIGH** | **CONFIRMED (measured)** |
| **SPIKE-F-2** | Two personas' onion services do **not** share introduction points | HIGH (as a *negative*) | **REFUTED (measured)** — halt condition §8.5 does not fire |
| **SPIKE-F-3** | `MaxStreamsCloseCircuit` is a **`Flag`**, not a `MaxStreamsCloseCircuit=1` argument; the argument spelling earns `512` from tor | MEDIUM | **CONFIRMED (measured)** |
| **SPIKE-F-4** | A production persona onion key belongs in `archival_p.rs`, not in a second cSHAKE256 path from the master seed | MEDIUM | **CONFIRMED (source)** |
| **SPIKE-F-5** | `ARCHIVAL_BOND_2D2_SP_T0_TOR.md` claimed SP-T0a delivered `ADD_ONION`/`DEL_ONION`. It did not | LOW | **CONFIRMED (source)** — corrected in this branch |
| **SPIKE-F-6** | The persona descriptor is a **liveness oracle** with ~3 h granularity, and it is an irreducible floor of running an onion service | MEDIUM | **CONFIRMED (measured)** |
| **SPIKE-F-8** | Two personas' descriptors land on **disjoint HSDir sets** (16 each, zero overlap) — the "shared HSDir" axis SP-T2 flagged does not exist | MEDIUM (as a *negative*) | **REFUTED (measured)** |
| **SPIKE-F-9** | `.gitignore`'s bare `bin/` rule silently untracks **any Rust crate's `src/bin/`** — Cargo's conventional binary location | MEDIUM (repo-wide) | **CONFIRMED (CI)** |
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

## 2. SPIKE-F-1 — guards are shared, and this is the serving axis's real finding

### The measurement

One tor, two personas added back to back, both publishing v3 onion services.
Circuit paths read from `GETINFO circuit-status`, attributed by which circuits
existed before the second `ADD_ONION`:

```text
persona 0 intro points: 1654A650 35F5A0B2 38CC95A8 6A801638 7FD2CD60 A3E13656
persona 1 intro points: 00B561BE 2705B1D3 506408D4 8FA37B93 BF54EE31 D7ABD3E5
INTRO_OVERLAP         : (empty)

persona 0 guards      : 7BBE05B2 843E20D6
persona 1 guards      : 7BBE05B2 843E20D6
GUARD_OVERLAP         : 7BBE05B2 843E20D6      <-- complete
```

Both personas' HS_SERVICE_INTRO and HS_SERVICE_HSDIR circuits enter the network
through the **same two guard relays**. This is not a defect in the
implementation — it is Tor's guard design working as intended (a small, stable
guard set is what limits malicious-guard exposure) — but it means:

> **SOCKS-username isolation is an outbound-only mechanism. `ADD_ONION` has no
> per-service isolation parameter at all.** SP-T2 proved per-`P` isolation on the
> *fetch* axis; that proof **does not transfer** to the serving axis, exactly as
> [`ARCHIVAL_BOND_2D2_SP_T2_FETCH.md`](ARCHIVAL_BOND_2D2_SP_T2_FETCH.md):134
> warned it would not.

### The threat tuple, and what it does *not* say

`T = ⟨`
- **who:** an operator of, or observer at, one of the wallet's entry guards (C2);
- **capability:** sees that one IP maintains N long-lived circuits with
  HS-service purposes, and their timing;
- **cost:** run a relay long enough to earn the Guard flag and be selected
  (weeks, plus bandwidth), or compromise/observe an existing one;
- **priced-where:** the C2 bucket in transport plan §7.
`⟩`

**What T learns:** *co-residency and cardinality* — "this host runs onion
services, and roughly how many." The guard sees circuits, not services: a v3
descriptor is encrypted, the intro point is three hops away, and nothing on the
circuit names the onion address.

**What T does not learn:** which `.onion` addresses these are. Completing the
linkage `persona A ↔ persona B ↔ this host` requires *additionally* binding an
onion address to this IP, which is the standard hidden-service location-discovery
problem that Tor's guard design exists to make expensive.

So the honest statement is: **guard sharing gives a co-residency channel, not an
address-linkage channel** — and it is *the* structural difference between the
client axis (isolated per persona, by construction) and the serving axis (not
isolated, with no knob to isolate it).

### Why the obvious mitigation is not obviously right

The mitigation is one tor instance per persona, each with its own guard set. That
is materially expensive (N processes, N `DataDirectory` trees, N bootstraps) —
but the decisive objection is not cost, it is that **it may be
counterproductive**: more guard sets means more independent guard draws, and each
draw is a fresh chance of landing on a hostile guard. Tor uses few guards
precisely because rotating and multiplying them is the worse failure mode.

**Disposition:** this is a design question for SP-T3 proper, not a spike
decision. It is recorded here with the measurement that grounds it, and it is the
single most important input this spike hands forward.

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
| Shared entry guards | **CONFIRMED** | Identical 2-guard set, measured (§2) |
| Shared HSDir set | **REFUTED** | Each persona uploaded its descriptor to **16 HSDirs; the two sets overlap in zero relays.** A v3 descriptor's directory position derives from the blinded key, which differs per service, so this is theory confirmed by measurement rather than luck. **No single HSDir sees both personas' descriptors.** |
| Correlated descriptor publication timing | **CONFIRMED (weak), and weaker than expected** | Two personas added **0.043 s** apart began publishing **0.98 s** apart — a tight, genuinely correlated window. But the HSDir result above blunts it: exploiting the correlation requires observing **≥ 2 of the 32 distinct directories** the two descriptors land on *and* correlating across them, because no directory sees both. Combined with the fact that two unrelated services starting at once on a busy directory look identical, this is a real-but-weak channel, not a break. `T = ⟨`multi-HSDir operator; sees upload times at the directories it runs; cost = running a meaningful fraction of the HSDir ring; priced in the C2/C3 bucket`⟩`. |
| `MaxStreams` exhaustion on A observable at B | **UNMEASURABLE-HERE** | Both services share one tor process, so shared-resource coupling is *structurally* present; but distinguishing "B degraded because A was flooded" from ambient Tor variance needs a controlled load generator and a quiet baseline, which this spike does not have. **Not claimed either way.** A design that assumes independence between co-hosted personas under load is unsupported by anything measured here. |
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

> **STATUS: the apparatus is complete and validated end-to-end against the real
> Tor network; the shard-payload run had not completed when this document was
> written.** The numbers below are filled by the `pd-f2-measure` binary. This
> section is deliberately left explicit rather than populated with a placeholder
> figure — see §13.

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

| Arm | Purpose | `N` |
|---|---|---|
| Cold circuit, single stream | Pessimistic; circuit build + rendezvous inside the timed path. The faithful model — each drawn miner *is* a different client | 200 |
| Warm circuit, single stream | Optimistic; circuit reused | 200 |
| 2 personas concurrent | §5.2 contention datum | 100 pairs |
| Soak, ≥ 24 h | Dispersion is time-varying; a one-hour sample understates the tail | continuous |

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

**As of this writing: INSUFFICIENT to select, and the reason is stated rather
than papered over.**

§8.3's two outcomes are different rounds:

- **Forceable** ⇒ sampling-plus-priced-deadline is live; TJ-A weighs the fork.
- **Not forceable** ⇒ receipt-attested transfer is the only branch, and §8.2 is
  the whole scope.

What is settled:

- The apparatus is real, validated end to end against the public Tor network, and
  rides the production hash-pinned tor.
- The payload is obtainable as a genuine shard at a known, modest cost.
- The statistical machinery reports `D*` correctly, including the two degenerate
  cases that a naive percentile would hide.

What is not settled: the distribution itself, which needs the ≥ 24 h soak. **The
24-hour arm cannot be short-circuited** — §8.3 names *circuit-latency dispersion*
as the load-bearing parameter, and dispersion is precisely the quantity a short
sample gets wrong. A number produced from a one-hour window would be a number
nobody should trust, which §10 of the charter names as the failure mode worse
than halting.

**"Insufficient" is a valid outcome and this is it, for now** — with the
apparatus, the payload path, and the statistics all in place, so producing the
number is a matter of running the soak rather than of further design.

---

## 14. What in this branch is disposable, and what may survive

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
  sharing) evaluated and **refuted**. SPIKE-F-1 (shared guards) is the spike's
  principal output. PD-F-2 distribution pending the ≥ 24 h soak.
