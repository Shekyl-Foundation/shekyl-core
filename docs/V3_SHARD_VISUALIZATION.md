# V3 Design Notes — Shard Visualization (Visual Identity Layer)

**Status:** V3 ship feature. Companion to `docs/V3_STAKER_ARCHIVAL.md`.
The archival mechanism functions without this; this layer makes
archival legible to humans. Originally drafted as V4-scoped; rescoped
to V3 by the 2026-04-27 actor-architecture decision-log entry, which
established `shekyl-shard-visual` as a domain-primitive library crate
(no actor wrapping; pure-CPU, async-free, deterministic) shipping
alongside the V3.x `ArchivalEngine` (Stage 5) ship.

This is a library crate, not an actor. The 2026-04-27 actor-
architecture decision pinned actor-shape as wrong for visualization:
no state to own (pure function from shard content to deterministic
image), no privacy boundary that needs actor enforcement (parameters
derive from public chain data), synchronous nature fights actor model
(wallet UI wants thumbnails *now* during portfolio rendering), and
multiple consumers want library access (block explorers, web
portfolios won't run an actor system).

The crate (`shekyl-shard-visual`) is referenced by:
`docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 — Engine architecture*
(domain-primitive library crate, "stays as-is" in the rename scope);
`docs/V3_STAKER_ARCHIVAL.md` (companion archival design that produces
the shards).

**Author / decision context:** Emerged in Phase 1 wallet-rewrite
session (2026-04-26) while exploring gamification of the shard
archival mechanism. The Pokemon analogy ("gotta collect 'em all") and
the Mandelbrot reference led to the realization that *deterministic
visual identity for chain state* is structurally meaningful, not just
eye candy. Rescoped to V3 ship in the 2026-04-27 actor-architecture
decision; the rescoping does not change the design — the crate-shape
makes shipping it cleanly possible within V3.x as a domain primitive.

---

## What this is

Each archival shard has a unique visual representation derived
deterministically from its content. Two stakers archiving the same
shard see the same visual; different shards produce different visuals;
the rendering is reproducible across implementations.

This is **deterministic data art** — the visualization is a faithful
rendering of the shard's content, not an artistic interpretation.

Three properties fall out of this:

1. **Visual integrity check.** Mismatched visuals between stakers
   indicate corrupt shard data, providing a cheap human-readable
   integrity signal that complements (not replaces) cryptographic
   verification.
2. **Legible rarity.** Active stakers playing the rare-shard market
   see *visually distinctive* rare shards, reinforcing the economic
   incentive with aesthetic incentive.
3. **Emergent chain identity.** Over time, the network develops
   informal folklore around specific shards' appearances. Cultural
   capital accrues without anyone designing it.

---

## What this is *not*

This is the section that matters most for getting the framing right.
Public communication about this feature must inoculate against three
prior crypto-art patterns that this is structurally distinct from.

### Not NFTs

NFTs as deployed had three properties this design explicitly rejects:

| NFT property | This design |
|---|---|
| Art exists separately from chain (off-chain image, on-chain pointer) | Visual *is* a rendering of chain state; no separate artifact |
| Scarcity is artificial (designer caps collection at N) | Scarcity is emergent from chain content |
| Economic value is speculative resale | Economic value is the archival service; visuals are not the product |

The visuals are not tokens. They are not separately addressable. They
do not have ownership records. They exist as rendered views of shards,
nothing more.

### Not tradeable

**Hard architectural constraint: the wallet does not support trading
shard visualizations.** This is non-negotiable and the constraint is
load-bearing for the V3 economic model.

The reasoning: every parameter in the V3 economy — lock-tier
multipliers, emission decay, burn rates, claim ranges, archival
reward formulas — is balanced against assumptions about *why
stakers stake*. The simulations validating these parameters
assume rational economic behavior driven by yield and archival
rewards.

Introducing tradeable visualizations creates a *separate* economic
dimension (collectible value) that wasn't in any simulation. Stakers
might:

- Choose shards by visual desirability rather than economic optimization
- Hold stakes longer than economically rational because they don't
  want to give up the visual
- Stake into specific shards to "mint" rare visualizations
- Develop a secondary market that prices visuals independently

Any of these distorts the carefully-balanced economy. The simulations
become invalid. The V3 economic model breaks.

This is the same class of failure mode as Ethereum's "add features
and figure out consequences later" pattern. Each addition looks
harmless in isolation; the cumulative effect is an economy nobody
designed.

**The discipline: visualizations exist because they make archival
legible, and for no other reason.** Anything that turns them into a
separate economic asset breaks the model. The enforcement-point
inventory below codifies the invariant (verified against landed code
2026-09-04; the FOLLOWUPS placeholder that scheduled it is removed
per rule 95 — resolved items are removed).

Concrete enforcement — **inventory verified against landed code
2026-09-04** (the FOLLOWUPS placeholder's trigger, "when implementation
begins", fired with the crate's first landing; this closes it):

- `shekyl-shard-visual` library API surface has no functions that
  mint, register, sign, or otherwise endorse an instance of a
  visualization. Pure
  `(shard_content) -> deterministic_image` only. *(Verified: no
  mint/transfer/register/owner symbol in `shekyl-shard-visual` or
  `shekyl-shard-source`.)*
- Wallet/daemon RPC surface has no methods that "own," "transfer,"
  "claim," or "register" visualizations. *(Verified: the RPC surfaces
  have no visualization methods at all; their only shard references
  are archival-assignment errors.)*
- Wallet UI has no "trade" button on shard visuals. *(Cross-repo
  claim, verified in the companion `shekyl-gui-wallet` repository —
  `src/components/staking/ShardIdentityPreview.tsx` has no
  trade/sell/transfer affordance; reproducible there, not from this
  tree.)*
- No wire format for transferring shard visual ownership.
  *(Verified: `ShardSummary` / `ShardRenderHandle` carry no owner.)*
- No on-chain registry of who "owns" a visual. *(None exists.)*
- Anyone holding a shard can render its visual at any time (no
  scarcity of *rendering*; scarcity is in *active archival*; complete
  shards are visible only to their holders, per ruling A's criterion).

A future PR that adds any such surface re-opens this inventory by
construction; the verification is a statement about the tree at the
date above, not a permanent property.

If a community proposal in V3.x or beyond suggests adding tradeability,
it gets evaluated against the simulation work that validated the
economy. If the simulation can't show that adding it preserves the
economic balance, it doesn't ship.

### Not "the chain's NFT layer"

The marketing/communication framing matters. Calling this "Shekyl
NFTs" or "Shekyl Pokemon" or anything that invokes prior crypto-art
baggage attracts the wrong audience and creates expectations the
mechanism shouldn't try to meet.

The correct external framing is something like:

> Shards have unique visual representations derived from their
> content, providing at-a-glance identity and integrity verification
> for stakers archiving the chain.

That's accurate. It signals what the feature does. It doesn't promise
speculation, tradeability, or collectability beyond the visual
distinctiveness itself.

A separate public-facing FAQ document should address the inevitable
"are these NFTs?" / "can I trade them?" / "is this a token?" questions
with explicit "no, here's why" answers. That FAQ is a V3.x shipping
concern, not a design-doc concern, but worth flagging that the
communication needs care.

---

## The mechanism

### Parameter derivation

Each shard's visualization is parameterized by characteristics derived
from the shard's content. Critically, **parameters are derived from
properties that are already public** — never from anything that wallet
privacy depends on.

Candidate derived properties, with their ruling-A dispositions
(*Parameter admissibility* below; the original draft called all of
these "public", which the sweep found untrue of the real chain):

- Shard hash (256 bits, uniformly distributed) — **admitted**
- Block count in shard — **admitted**
- Transaction count (aggregate) — **admitted**
- Time range (first block timestamp to last block timestamp) — **admitted**
- Output count (new outputs in the shard's block range) — **admitted**
- Coinbase ratio (proportion of outputs from miner emission vs. user
  transactions; count-based) — **admitted, derived from counts**
- Stake event count (stakes created, stakes claimed) — **rejected for
  now** (rule 21; no ratified holder-readable surface yet)
- Distribution moments of output values — **rejected** (CT hides user
  output amounts; not computable from held bytes)

The design-review checkpoint this list anticipated has run: it is
ruling A's sweep, below.

The shard hash provides the bulk of the "uniqueness" entropy. The
content-derived properties make the visual *say something true* about
the shard rather than being a pure hash visualization. A shard from a
high-activity chain period looks visibly different from a quiet-period
shard; experienced stakers learn to read this.

## Parameter admissibility (ruling A)

### The admissibility criterion (pre-registered 2026-09-04)

This criterion is registered **before** the feature-by-feature sweep, so
that every feature is judged against the same standard rather than one
derived while walking the list. It is the design-review checkpoint from
*Privacy considerations* below, stated as a testable rule:

> **A feature is admissible iff it is a deterministic function of data
> any holder of the shard can read from the shard's serialized blocks —
> no key, no wallet state, no holder-specific privilege — so that a
> rendering publishes nothing about the shard that holding the shard
> does not.**

Two clarifications that do work:

- **"Holder" is the population, not the network.** Complete shards are
  visible only to those who hold them (or otherwise have them on their
  machine); the criterion is *holder-computability from held block
  bytes*, not queryability over the network. This matches the original
  framing ("computable by anyone holding the shard") and is what makes
  the rendering an integrity check between holders.
- **Aggregation is a design preference, not the privacy criterion.**
  Features should be shard-wide aggregates for legibility and
  continuity, but aggregation is neither necessary nor sufficient for
  admissibility — an aggregate over data the chain hides (e.g. a mean
  of confidential amounts) fails the criterion however aggregated.

### The closed-world artifact property

The criterion above is the feature-level application of a closed-world
rule over the whole rendering:

> **A rendering is a deterministic function of
> (shard content, spec version) — and of nothing else.**

The *and of nothing else* is load-bearing: any future input to the
rendering — a new feature, a wallet setting, a locale, a device
property — is a violation **by default** and must pass this section's
criterion (and re-ratify this section) to be admitted. The burden runs
toward exclusion; nothing is grandfathered by being convenient.

### The sweep (2026-09-04) — verdicts on the shipped feature set

**Root cause, first, because it explains how the checkpoint inverted
without anyone noticing:** the feature set was designed against the
`shekyl-dev/visualization/` fake chain, which *publishes things the
real chain hides* — cleartext output amounts, cleartext stake tiers.
Every feature looked public in the explorer because the explorer's
chain made it public. This is a corpus-fidelity defect, not reviewer
negligence, and the criterion above is stated against *held real block
bytes* precisely so the fake chain can never again stand in for the
real one in an admissibility argument.

Verdicts on the nine features `features_from_aggregate` computed, plus
the two aggregate fields that were not features:

| Feature / field | Verdict | Ground |
|---|---|---|
| `activity_density` (tx per block) | **ADMIT** | tx and block counts are in held block bytes |
| `output_richness` (user outputs per tx) | **ADMIT** | output counts are in held block bytes; coinbase txs are structurally distinguishable |
| `coinbase_ratio` | **ADMIT, as a derived feature** | count-based (`coinbase_output_count / output_count`); computed in `features.rs` from the two counts — the redundant wire field on `ShardAggregate` is deleted (one value, one meaning) |
| `time_density` | **ADMIT** | block timestamps are in held block bytes (currently unconsumed by candidate.v1; whether it drives aesthetics is ruling B's call) |
| `value_magnitude`, `value_dispersion` | **REJECT** | user output amounts are Pedersen commitments (CT; `docs/FCMP_PLUS_PLUS.md`). Even a holder of every byte of the shard cannot compute value moments without recipient keys — the criterion fails at computability, before any leak analysis is needed |
| `tier_skew_high` (from `tier_distribution`) | **REJECT** | stake tier is confidential-staking material: the F-ARCHIVAL resolution adopted tier-neutral shard pricing *specifically to kill the portfolio tier oracle* (`docs/V3_STAKER_ARCHIVAL.md`), and post-F0 the tier is not in block bytes. Rendering it would re-expose what that redesign deliberately removed |
| `stake_intensity`, `claim_create_ratio` | **REJECT-NOW, reopening criterion named** (rule 21) | no ratified consensus surface makes per-shard stake-create or claim event counts a holder-readable quantity today (principal-stake lifecycle is mid-design-round; the reward-emission leg is unbuilt). Re-admit — by re-ratifying this section — when the respective surface lands and its per-shard event count is readable from held shard bytes |
| `dominant_regime` | **not chain data** | fake-chain corpus classifier; moved off `ShardAggregate` onto the fixture type (`PreviewFixture`), where corpus annotation belongs |

Enforcement is in the same change as this text: `ShardAggregate` now
carries only `shard_id`, `shard_hash`, and the admitted counts and
timestamps; `Features` carries only the four admitted scalars. Renderer
inputs that consumed rejected features now draw from the renderer's own
SHAKE256 structural namespace at previously-unused indices (hash-derived,
so they publish nothing and per-shard visual diversity is preserved);
the resulting aesthetics are ruling B's to close.

### Spec version is chain data (algorithm-versioning ruling)

The "Algorithm versioning" open question below is ruled on its privacy
half: **the rendering-spec version is chain data — an activation height
— never wallet data.** A shard renders under the spec version active at
its creation height, immutably (path (a)).

The discriminator is this document's own property 1 (the visual
integrity check): under re-render-with-latest (path (b)), a stale
wallet and an upgraded wallet mismatch on the *same* shard throughout
every upgrade window — the integrity signal false-alarms exactly when
the network is paying attention to versions. Under (a), an old wallet
shows an explicit "newer spec" placeholder for a post-upgrade shard and
never a wrong picture. Path (b) would also make every shared image a
fingerprint of the sharer's wallet version, violating the closed-world
property (a rendering would be a function of wallet state). Cost of
(a): conforming implementations carry superseded renderers; spec
versions are expected to be rare enough that this is bounded.

Enforcement of the height pin lands with the Stage 5 cutover, when
shards acquire creation heights — the named blocker (rule 22): no
height exists for a fixture aggregate, and only one spec version
exists today. What lands now is the operand: every `CandidateRecipe`
carries `spec_version` (`"candidate.v1"`), so exports are
self-describing and the future comparison has its field.

### Overridden renders are visibly non-canonical (hash-override ruling)

The preview tweak path (`hash_override`, structural overrides,
synthetic feature vectors) produces **viewer-chosen artifacts, not
chain state**. That category is acceptable *because it is stated*: an
override render indistinguishable from a canonical one would poison
the same integrity check the feature exists to serve. Enforcement is
typed, not conventional, and unforgeable from outside the crate
(review #617): `RenderParameters`' fields are crate-private, its
constructors decide `canonical`, and the only public mutation
(`push_structural_override`) can weaken the claim but never restore
it. `CandidateRecipe.canonical` derives from
`RenderParameters::is_canonical`, so every exported recipe carries the
marker — and the PNG bytes themselves carry it too: every render stamps
`tEXt` provenance chunks (`shekyl.spec_version`, `shekyl.canonical`),
so a saved file stays self-describing with no recipe attached. The one
render entry point (`render_candidate_png_from_params`) derives pixels,
chunks, and recipe from the same parameter bundle, so they cannot
disagree.

**Scope of the claim (one value, one meaning).** `canonical` attests
the *render pipeline's* provenance: the pixels were derived from the
aggregate handed to the constructor, unmodified, with no override and
no synthetic input. It does not attest that the aggregate is truthful
chain data — the renderer is a pure function and cannot know; that
binding belongs to the layer that produces aggregates
(`shekyl-shard-source` rejects a stale handle whose hash disagrees
with the resolved aggregate today; `ArchivalEngine` supplies verified
shards at Stage 5). Asking the render layer to verify its input
against the chain would put a chain-integrity check at a
pure-function boundary that has no chain access — the same
wrong-layer shape as demanding wire properties of a seal-admission
check.

## Rendering determinism and empirical closure (ruling B)

Ratified 2026-09-05 (all three questions as packaged, corrections in
force). The measurement half — goldens, KATs, the avalanche test, the
floor-device budget matrix — **was executed 2026-09-06**; see
*Measurements of record* below. This section remained its
precondition, because the thresholds below are
**pre-registered**: they were fixed before any cross-platform run
produced a number, and they may change only by a recorded amendment
citing the measurement that motivated it, never by quiet retuning. A
threshold set after the measurement would be whatever the measurement
happened to yield.

### The layered determinism bar

The derivation splits into two layers with different natural bars, and
the ruling commits to both rather than averaging them:

- **Hash-derived structure — bit-exact, forever.** The SHAKE256 draws,
  palette and algorithm assignment, opacity quantization, and the
  whole `CandidateRecipe` are integer/quantized arithmetic. They are
  bit-exact across platforms and across implementations today, pinned
  by the twin Rust/Python golden-recipe KATs (same literals on both
  sides). Falsified by any recipe field differing on any platform or
  implementation.
- **Raster — perceptual, against committed goldens.** The renderer
  interiors use `f64` transcendentals whose last-ulp behaviour is
  platform-dependent; the bar for the painted pixels is a
  pre-registered metric, not byte equality.

**The oracle's axis is decoded pixels, never PNG file bytes.** The PNG
container passes through the encoder's compression, adaptive
filtering, and the ruling-A provenance `tEXt` chunks — a byte
comparison would measure the compressor, not the picture. Every
raster comparison decodes first.

**Pre-registered raster metric and threshold.** The metric is
per-pixel RGB root-mean-square distance: decode both images to RGB8 at
identical dimensions, RMS over all pixels and channels, on the 0–255
scale. The threshold is **θ = 2.0**. Reasoning, registered with it:
the pipeline is exact everywhere except renderer-internal
transcendentals, so cross-platform divergence can enter only as
isolated boundary-rounding jitter — a coordinate rounding differently
on rare pixels — which leaves almost every pixel identical and RMS
well under 1. The defect classes the oracle exists to catch sit an
order of magnitude above: a wrong palette shifts the whole image
(RMS ≈ 30+), a dropped element (the class round 3 actually found —
the unfilled edge outlines) or a wrong structural draw moves several
percent of pixels at large deltas (RMS ≈ 10–20). θ = 2.0 splits the
gap with roughly an order of magnitude of margin on each side. If an
honest cross-platform run exceeds θ, that is a finding to adjudicate
in the open — amend this section with the measurement attached — not
a dial to turn.

**Goldens are committed once, from a designated reference run** (named
implementation, named architecture, named commit), and are never
regenerated by the tests that consume them. Both implementations pin
to the same committed artifact — never to each other at runtime. A
parity test whose reference is the port under test proves nothing;
that is how the dropped edge outlines stayed invisible.

### Retraction, with its reopening criterion

The bit-equivalence claims in *Implementation notes* below (struck
through in place, not deleted) are **retracted**: the shipped
transcendental-float renderers cannot produce bit-equivalent rasters
across x86/ARM/WASM, and rewriting a non-consensus aesthetic surface
in fixed-point buys nothing the layered bar does not. **Reopening
criterion (rule 21):** the claim becomes ratifiable again if a
deterministic rasterizer is ever pinned across both implementations —
that event, and nothing softer, reopens this decision. Standing
invariant either way: no protocol or reward surface may ever consume
a rendering; if one ever proposes to, bar (a) must be revisited first.

### Sensitivity, not continuity

*Reorg behavior* below previously promised that small reorgs produce
small visual changes. **That text was wrong as written, not merely
imprecise**: it was authored for the retired single-algorithm design
and was never carried into candidate.v1, under which palettes,
opacities, and structural draws all derive from the shard hash through
SHAKE256 — one changed block avalanches the hash and the whole
picture. More importantly, continuity and integrity-detection are in
**direct opposition** here: a rendering whose job is making corruption
visible should have maximal sensitivity, and the old text asked for
the property that defeats the feature's purpose — implemented, it
would have been a silent-corruption hazard. The ratified property is
**sensitivity**: any change to shard content produces a large, obvious
visual change; magnitude carries no information.

**Avalanche falsifier, both limbs pre-registered.** Flip one bit of a
fixture's shard hash and render both: the raster metric must show a
distance **≥ 20** (the pre-registered floor, same amendment
discipline as θ). The second limb is what makes this a test rather
than a demonstration: if any two adjacent hashes ever render
near-identical pictures, the property is falsified — and the first
limb alone would pass against a broken renderer that ignores its
input entirely, since any hash function avalanches whether or not the
pixels listen to it.

### Floor-device budget (measured 2026-09-06: falsified at every tier)

The *Performance targets* below are provisioned at the floor device
(`rule 76`: Pi 4), measured **on the floor only**. An x86 measurement
cannot bound the floor in either direction: measured per-term x86:A72
ratios span 3.86×–12× **with one axis changing sign**, so no single
scaling factor exists. Falsifier: any (fixture, size) cell over budget
on the floor falsifies candidate.v1's fitness at that tier, with this
document's stated consequence (drop or restrict what misses; the
single-algorithm fallback remains the documented escape). The
thresholds were the targets already printed below, which predate the
measurement. **Result: all 36 (fixture, size) cells came in over
budget** — see *Measurements of record* directly below. Which of the
three gives was not a measurement's call; it was ruled separately on
2026-09-06 (**the budget gives**), and the amendment that follows from
it is recorded in *Performance targets*.

### Measurements of record (2026-09-06)

Executed under the pre-registered thresholds above, none of which were
touched. Reference run producing the committed goldens
(`rust/shekyl-shard-visual/tests/goldens/`): the Rust crate at
`655d31cb2`, release profile, rustc 1.94.0 (the version
`rust/rust-toolchain.toml` pins; the machine's default 1.95.0 does not
apply inside `rust/`), x86_64-unknown-linux-gnu
(i9-11950H). Floor device: `skl-pi`, Raspberry Pi 4 Model B Rev 1.4,
aarch64, binaries cross-compiled from the same commit. Thermal
regime: 50.6 °C at start, 59.4 °C at end, governor verified reaching
stock 1800 MHz under load mid-render. The firmware throttle flag is
unreadable without root, so the temperature bracket plus the
sustained-frequency check stand in for it: they establish that the
conditions for throttling were absent, which is the claim these
numbers support (not the stronger "no throttling occurred").

**Raster parity (θ = 2.0): RMS = 0.000000 on all nine fixtures, at
128px.** The aarch64 raster is bit-identical to the x86-committed
goldens — the anticipated boundary-rounding jitter did not appear at
all on this architecture pair. **Scope: 128px only.** The falsifier is
quantified over (platform, fixture, size) cells, and goldens exist at
one size, so parity at 256/512/1024px is *unmeasured*, not measured
clean; committing goldens at every size would quadruple-plus the
repo's binary weight for sizes that share one code path. Recorded as
measured, at the size measured. **This does not reopen the
bit-equivalence retraction**: the reopening criterion is a
deterministic rasterizer *pinned across both implementations*, and
one architecture pair happening to agree is an observation, not a
pin — two architectures agreeing today says nothing about a third
architecture, a WASM target, or a toolchain bump on either side. The
perceptual bar stays the ruled bar; a measurement that *looks like*
it satisfies a criterion is precisely where a criterion quietly
dissolves, so the zero is recorded and the criterion is restated.

**Avalanche (floor ≥ 20): sweep minimum RMS = 34.165** (drain_burst,
byte 15 bit 3), identical on x86 and aarch64, over 9 fixtures × 3 bit
positions (first byte, interior, last byte) on the pixel axis, at
128px. Sensitivity holds with ~1.7× margin. Same size caveat as
parity: bit positions and sizes outside the sweep are unmeasured.

**Budget matrix: 36/36 cells over budget.** Median of 5 timed runs
after 1 warm-up, single-threaded, full render-plus-PNG-encode path
(`examples/budget_matrix.rs`), release profile. **The full 36-cell
table, per fixture, with the thermal bracket and toolchain manifest,
is committed at
[`docs/benchmarks/shard_visual_budget_matrix_pi4_20260906T090000Z.txt`](benchmarks/shard_visual_budget_matrix_pi4_20260906T090000Z.txt)**
— the summary below compresses it, and the per-fixture spread is the
part a ruling may turn on. Per-size medians across the nine fixtures,
against the targets:

| size   | budget  | floor medians (min–max) | over by   |
|--------|---------|-------------------------|-----------|
| 128px  | 50 ms   | 69–164 ms               | 1.4×–3.3× |
| 256px  | 100 ms  | 155–385 ms              | 1.6×–3.9× |
| 512px  | 300 ms  | 535–1781 ms             | 1.8×–5.9× |
| 1024px | 2000 ms | 2685–12440 ms           | 1.3×–6.2× |

Worst fixture: `coinbase_heavy` (12.4 s at 1024px). Best:
`confidential_stake` (2.7 s at 1024px), still over in every cell —
a **4.6× spread across content at one size**, so render cost is
strongly fixture-dependent, not a flat per-pixel constant. Stated as
an observation the ruling may want; this document does not draw a
conclusion from it. For orientation only
(non-probative for the floor, per this section): the x86 reference
machine also missed 512px and 1024px on 5 of 9 fixtures. **This is a
falsification, not a gap: candidate.v1 as specified does not fit the
stated minimum device at any tier**, and the magnitudes rule out
tuning as the answer — 6.2× at 1024px is not a constant factor away
from fitting. The documented escape (drop or restrict what misses;
single-algorithm fallback) cannot be applied selectively when every
cell misses. The measurement itself ranked none of the three things
that could give — the budget, the candidate, or the floor device.

**RULED 2026-09-06 (Rick): the budget gives.** *"The scores on the Pi
for shard rendering are acceptable."* The implementation and the floor
device both stand; the original figures were the wrong numbers. The
replacements, their derivation, and the change in what they assert are
recorded as a dated amendment in *Performance targets* below. This
paragraph stays as the record of the falsification that forced it.

## Candidate compositor (candidate.v1) — leading V3.x design

Empirical exploration in `shekyl-dev/visualization/` (2026-05) converged on a
**two-stage difference compositor** rather than the single-algorithm 3-bit
bucket assignment described below. This pipeline is the **leading design** for
the V3.x `shekyl-shard-visual` reference implementation pending formal palette
closure:

1. **Foreground composite** — `aperiodic_tile` ⊖ `phyllotaxis`, difference
   blend, opacity from `candidate.v1.fg.opacity` (bell curve, mean 0.5).
2. **Background composite** — `truchet` ⊖ `crystalline`, difference blend,
   opacity from `candidate.v1.bg.opacity` (same bell shape).
3. **Final composite** — background ⊖ foreground, difference blend, opacity
   from `candidate.v1.final.opacity` (high bell, mean ~0.80).

Palettes and per-layer opacities are hash-derived via SHAKE256 namespaces
(`candidate.v1.fg`, `candidate.v1.bg`, `candidate.v1.*.opacity`). Feature
scalars from the shard aggregate drive renderer aesthetics inside each
algorithm. The single-algorithm palette in the sections below was the
**fallback spec shape** if candidate.v1 failed mobile budget or continuity
review. **Both conditions have now resolved and the fallback is RETIRED
(2026-09-06)** — see *Fallback disposition* below. The sections that
describe it are kept as the record of the algorithms considered, not as
a live alternative.

#### Structural entropy: one SHAKE256 namespace per renderer

Each of the four renderers draws its **structural** parameters (orientation,
divergence perturbation, foreground tone, circle-map ω/K/phase, scatter seed,
palette-spread jitter) from its own namespaced stream:

| Renderer         | Namespace                        | Indices used        |
|------------------|----------------------------------|---------------------|
| `aperiodic_tile` | `shard.v1.render.aperiodic_tile` | `unit(0..3)`        |
| `phyllotaxis`    | `shard.v1.render.phyllotaxis`    | `unit(0..4)`        |
| `truchet`        | `shard.v1.render.truchet`        | `unit(0..1)` + per-cell `Sha256`|
| `crystalline`    | `shard.v1.render.crystalline`    | `unit(0..2)`, `uint32(3..4)`, `unit(5)`|

Indices `2..3` (aperiodic), `3..4` (phyllotaxis), `1` (truchet) and `5`
(crystalline) were added by ruling A: structural draws that replace the
rejected features those renderers previously consumed, at
previously-unused offsets so the pre-existing draws are unchanged.

Rationale: the legacy layout carved the 256-bit hash into eight little-endian
`uint32` words and let every renderer index the *same* pool, so renderers that
both read word 0 produced structurally-correlated geometry for the same shard,
and the eight-word budget did not stretch across all four algorithms without
reuse. SHAKE256 is an XOF, so each `(shard_hash ‖ 0x01 ‖ namespace)` seed
yields an independent, unbounded stream — distinct indices in distinct
namespaces are statistically uncorrelated. `aperiodic_tile` previously consumed
**zero** hash entropy (identical feature vectors produced identical geometry);
it now draws a rosette rotation and palette-spread jitter so every shard is
visually distinct. The Rust reference and the Python explorer use byte-identical
derivation (same primitive, same domain separator, same little-endian word
layout), so the two implementations agree on the structural draws.

### Pre-archival preview exception (GUI wallet)

Before `ArchivalEngine` (Stage 5) ships, the GUI wallet may expose a
**beta preview** on the Staking page that renders **fixture aggregates**
(illustrative fake-chain samples) and optional user-supplied shard hashes with
preset feature vectors. This is **not** production archival UI; it validates
the `shekyl-shard-visual` library and gives stakers a tangible preview of
deterministic shard identity. Production cutover replaces fixtures with real
archived shards from `ArchivalEngine`; cache keys use `(shard_id,
shard_content_hash)` per below.

---

### Visualization palette: hybrid approach

A single visualization algorithm risks "they all look the same kind
of thing" fatigue across thousands of shards. The recommended approach
is a small palette of candidate algorithms, with each shard assigned
one based on hash bits.

Candidate algorithms (all are deterministic, reproducible, and
computationally cheap):

#### 1. Mandelbrot / Julia sets

Classic fractals parameterized by complex coordinates. The shard hash
provides the parameter; the rendering is a colored escape-time map.
Aesthetically rich, mathematically clean, well-understood by
implementers.

Reference: see Wikipedia's [Julia set](https://en.wikipedia.org/wiki/Julia_set)
and [Mandelbrot set](https://en.wikipedia.org/wiki/Mandelbrot_set)
articles for examples of the visual range these produce. Different
parameter regions of Mandelbrot space produce dramatically different
visuals — spirals, lightning, dendrites, sea-horse valleys.

**Cost:** moderate. Iteration-based; depth controls quality. Target
~50ms at 256x256 resolution on mobile; faster on desktop.

**Continuity:** good. Small parameter changes produce small visual
changes (mostly — there are bifurcation regions where this fails).

#### 2. Voronoi diagrams

A set of seed points (derived from hash bits) partitions the plane
into cells; cells are colored based on derived properties. Highly
distinctive per shard; cellular aesthetic.

Reference: see Wikipedia's [Voronoi diagram](https://en.wikipedia.org/wiki/Voronoi_diagram)
article for algorithmic detail and visual examples.

**Cost:** very cheap. Linear-ish in seed count. Sub-10ms easily.

**Continuity:** excellent. Adding/removing seeds shifts cells locally
without global change.

#### 3. L-system / generative botanical

A grammar of replacement rules (derived from hash) iterated N times
produces a branching structure. Trees, ferns, plant-like patterns.
More organic-looking than fractals.

Reference: see Wikipedia's [L-system](https://en.wikipedia.org/wiki/L-system)
article — the standard "fractal plant" examples there illustrate the
output space.

**Cost:** depends on iteration count. Bounded if you cap iterations.
Sub-50ms at reasonable depth.

**Continuity:** poor. Small grammar changes can produce wildly
different outputs. Use only with hash-stable parameter mappings.

#### 4. Strange attractors (Lorenz, Rossler, etc.)

A 3D dynamical system traced through phase space, projected to 2D.
Coefficients derived from hash. Curves through space, visually flowy.

Reference: see Wikipedia's [Lorenz system](https://en.wikipedia.org/wiki/Lorenz_system)
article — the iconic "butterfly" attractor and variants. The
[List of chaotic maps](https://en.wikipedia.org/wiki/List_of_chaotic_maps)
catalogs additional candidates (Rössler, Chen, Thomas, etc.)
that all produce distinctive visuals.

**Cost:** moderate. Integration-based; step count controls quality.

**Continuity:** good in stable parameter regions, poor near chaotic
transitions. Use parameter ranges known to be visually stable.

#### 5. Reaction-diffusion (Turing patterns)

A two-chemical simulation produces self-organizing patterns —
spots, stripes, labyrinths. Resembles the patterns on seashells and
animal markings. Hash-derived parameters drive the simulation.

Reference: see Wikipedia's [Reaction–diffusion system](https://en.wikipedia.org/wiki/Reaction%E2%80%93diffusion_system)
article and the [Turing pattern](https://en.wikipedia.org/wiki/Turing_pattern)
article for examples.

**Cost:** higher than the others. Requires running a simulation to
steady state. May be too expensive for mobile rendering at full
resolution.

**Continuity:** good. Smooth parameter changes produce smooth pattern
changes.

**Recommendation:** include only if a low-resolution variant can hit
the rendering budget. Otherwise drop from the palette.

#### 6. Phyllotaxis / spirals

Sunflower-seed-style spiral arrangements. Parameterized by the
divergence angle and seed density (both hash-derived). Visually
distinctive, mathematically elegant.

Reference: see Wikipedia's [Phyllotaxis](https://en.wikipedia.org/wiki/Phyllotaxis)
article — the Vogel model produces particularly clean visuals.

**Cost:** very cheap. Linear in seed count.

**Continuity:** good. Small angle changes produce visible but bounded
shifts.

#### 7. Flow fields / Perlin noise visualization

A 2D vector field (derived from hash-seeded noise) traced by particles
produces flowing curve patterns. Smooth, painterly aesthetic.

Reference: search for "flow field generative art" — this is a
well-trodden technique in the generative-art community. Examples are
abundant on platforms like OpenProcessing or KhanAcademy.

**Cost:** moderate. Particle count controls quality.

**Continuity:** excellent. Smooth by construction.

### Algorithm assignment

Each shard's hash bits determine which algorithm it uses. Distribution
should be roughly uniform across the palette to avoid over-clustering
on any one type. The assignment is deterministic — same shard always
renders with the same algorithm.

Reasonable initial split (using 3 hash bits → 8 buckets, with one
algorithm spanning multiple buckets to balance cost):

| Hash bits | Algorithm |
|---|---|
| 000 | Mandelbrot |
| 001 | Julia set |
| 010, 011 | Voronoi (more buckets — cheap, distinctive) |
| 100 | Strange attractor |
| 101 | Phyllotaxis |
| 110 | L-system (botanical) |
| 111 | Flow field |

Reaction-diffusion is omitted from the initial palette pending cost
analysis. Can be added in a later version if performance permits.

### Color palettes

Each algorithm has a small set of color palettes (derived from
additional hash bits). This adds a second axis of variation without
increasing algorithm count. Palettes should be:

- **Visually distinct** from each other (so two shards using the same
  algorithm but different palettes look clearly different)
- **Accessible** (readable for color-blind users; sufficient contrast
  to render legibly at small sizes)
- **Unmetaphorical** (avoid loaded color associations — no "red =
  rare" type semantics, since rarity is shown elsewhere in the UI)

Candidate palette families: jewel-tones, pastel, monochrome, neon,
earth-tones, prismatic. Six palettes × seven algorithms = 42 broad
visual categories before content-derived parameter variation, which
is plenty for a network with thousands of shards.

---

## Ruling B's assigned residue — closed 2026-09-06

Three items the sweep and the compositor section handed to ruling B by
name, which ruling B did not close. Ruled together by Rick, 2026-09-06.

### `time_density`: KEPT

The sweep admitted `time_density` and left "whether it drives
aesthetics" to ruling B. **Ruling: keep the field.** It remains
admitted, computed in `features.rs`, and currently read by no renderer —
a deliberate dormancy, not an oversight, and this paragraph is what
makes it deliberate. Deleting it was the alternative considered and
rejected; a later change that gives the visuals a time axis needs no
re-ratification of admissibility, because the sweep already cleared it
as holder-readable.

### Post-rewire aesthetics: ACCEPTED as they stand

Ruling A rewired renderer inputs from rejected features to hash draws
and left "the resulting aesthetics" to ruling B. The corpus was
rendered at 512px and at the 128px thumbnail size and inspected.
**Ruling: accepted; no change.**

One reported finding was **withdrawn under measurement** rather than
carried, and is recorded because the withdrawal is the useful part. The
claim was that distinguishability collapses at the 128px product size —
that several fixtures converge on similar muted mid-tones once fine
structure averages away. Measured pairwise over the nine fixtures, it
does not hold: full-image RGB-RMS is **min 42.0 / median 53.5 at
128px** against **min 42.9 / median 57.8 at 512px**, and the closest
mean-colour pairs sit at ≈5 at *both* sizes. Distinguishability is
size-independent across the corpus; the claim was an impression of a
thumbnail strip, not a property of the renders.

What is true, and is not a defect: a few pairs are close in mean colour
at every size (`genesis`/`active`, `genesis`/`confidential_stake`).
With six palettes and nine fixtures, colour collisions are expected by
pigeonhole — the discriminating signal is structure plus colour, and
full-image RMS above 42 for every pair is what carries it.

Also noted and **not** changed: the `crystalline` layer plots its
circle-map orbit at a constant `y` (`ys = k / 2.0`), so it contributes
one bright horizontal line at a hash-derived height rather than a
two-dimensional scatter. The Rust port is faithful — the Python
reference does the same and calls it "a horizontal scatter" — so this
is not the ported-renderer divergence class. Latent, for whoever
revisits the renderer: that reference's own docstring attributes the
aesthetic to "Arnold-tongue structure … showing as bright vertical
bands", which an orbit plotted at constant `y` cannot produce. The
reference implements something other than what it describes. Changing
it changes pixels and carries the full cascade below.

### Fallback disposition: the single-algorithm palette is RETIRED

The compositor section made candidate.v1 the leading design "pending
formal palette closure", with the single-algorithm palette as the
fallback "if candidate.v1 fails mobile budget or continuity review".
**Both trigger conditions have resolved**: continuity was ruled the
wrong property (sensitivity replaced it), and the mobile budget was
measured on the floor device with the ruling that *the budget gives*,
not the candidate. The condition that would have promoted the fallback
cannot now fire.

**Ruling: candidate.v1 is the palette; the fallback is retired.** The
algorithm sections below stay as the record of what was considered —
they are not a live alternative, and no one should reconcile a second
design against the first. **Reopening criterion (rule 21):** a
floor-device measurement that candidate.v1 cannot be made to satisfy,
after the amended targets have themselves been re-derived — that event,
and nothing softer, reopens this.

### What a pixel change would cost

Recorded here because two of the three items above could have gone the
other way, and the enforcement exists precisely so this cannot happen
quietly: bump `RENDER_REVISION` or CI's
`scripts/ci/check_golden_revision_bump.py` fails the change; regenerate
the nine goldens from a clean tree (`_reference_run` must record
`dirty: false`); regenerate the Python twin's copy of `recipes.json` if
any recipe field moves; and re-run the floor budget matrix on `skl-pi`,
committing the capture — the change would be inside the timed path.

## Rendering discipline

### Performance targets

**AMENDED 2026-09-06 — recorded amendment, per the amendment
discipline in *Rendering determinism and empirical closure*.**
Authority: Rick's ruling, *"the scores on the Pi for shard rendering
are acceptable"* — of budget, candidate, and floor device, the
**budget gives**. **Confirmed:** the ruling arrived relayed through a
coordinating session and was then confirmed by Rick directly to
steering on 2026-09-06 ("Shard visual B is ratified"). Recorded that
way because a relayed ruling is not a signature — the confirmation is
in-channel, not an artifact in this tree, and the record should say
which it is. Evidence: the 36-cell floor matrix,
[`docs/benchmarks/shard_visual_budget_matrix_pi4_20260906T090000Z.txt`](benchmarks/shard_visual_budget_matrix_pi4_20260906T090000Z.txt),
which falsified every cell of the original figures. The originals are
struck through below, **refuted, not superseded**.

#### Why the originals failed: they named no statistic

The lead finding is not that the numbers were too aggressive. It is
that "sub-50ms at 128px" names **no statistic and no device state**.
Median, p95, and worst-case differ by more than the numbers do, so
the targets were **never falsifiable** — and an unfalsifiable
threshold generates no failures, so nothing ever forced a look. That
is why they survived years unexamined. A threshold without a
statistic is not a threshold.

Every replacement below is stated as **median on the floor device,
warm, otherwise idle** — the exact quantity
`rust/shekyl-shard-visual/examples/budget_matrix.rs` emits (median of
5 timed runs after one untimed warm-up, single-threaded, full
render-plus-PNG-encode, architecture recorded).

#### These are regression bounds, not fitness bounds

The struck-through figures asserted **fitness**: candidate.v1 must fit
the floor device. The replacements do a **different job**, and saying
so is load-bearing. At ~2× the measured corpus-worst, nothing the
current implementation does can breach them — presented in the old
voice they would be *a check that cannot fail*.

> These thresholds no longer assert that the design fits a UX target.
> They assert that it has **not regressed from the measured floor
> baseline**. The UX question is answered by the async and caching
> consequences below instead.

#### Amended targets

| tier | original | corpus-worst floor median | **amended** |
|------|----------|---------------------------|-------------|
| Mobile thumbnail (128×128) | ~~sub-50 ms~~ | 164 ms (`active`) | **350 ms** |
| Portfolio view (256×256) | ~~sub-100 ms~~ | 385 ms (`coinbase_heavy`) | **800 ms** |
| Detail view (512×512) | ~~sub-300 ms~~ | 1781 ms (`coinbase_heavy`) | **4 s** |
| Share / print (1024×1024) | ~~sub-2 s~~ | 12440 ms (`coinbase_heavy`) | **25 s** |

**Margin: 2× over the corpus-worst floor median.** Under a regression
reading the margin is a **false-positive budget** — too tight and the
check reddens on thermal noise until people learn to ignore it, and
*a threshold people learn to ignore is worse than no threshold
because it looks like coverage*; too loose and a real regression
slips. Three one-sided sources of variation justify it, each able to
make a real render slower and never faster:

1. **The corpus cannot contain the worst case.** Nine fixtures, one
   per regime of a *fake* chain, chosen for aesthetic diversity, not
   render cost. Measured content-dependence is **4.6× at one size**
   (`coinbase_heavy` 12.4 s vs `confidential_stake` 2.7 s at
   1024px), so real-chain shards plausibly exceed the measured max.
2. **Measurement conditions were favourable; a wallet's are not.**
   Device idle at load 0.00, one render at a time, every timed cell
   preceded by an untimed warm-up. A wallet renders while scanning
   and syncing.
3. **Thermal, quantified.** The run ended at 59.4 °C after minutes,
   not hours, at stock 1800 MHz. A passively cooled Pi 4 under
   sustained load throttles toward 1.0–1.5 GHz — **up to ~1.8×
   slower on clock alone**, which nearly consumes 2× by itself and
   leaves sources 1 and 2 unfunded.

**Reopening criteria (rule 21) — the two things that would justify
tightening:** a matrix over a **real** shard corpus (moves source 1
from unquantified to measured), or a **sustained-load thermal run**
(turns source 3 from a bound into a number). Absent one of those, the
margin does not move.

#### Consequences these numbers oblige (rules 80, 82)

- **128px / 256px stay interactive only because the render is
  cached** by the GUI's `cache_digest` (which includes
  `RENDER_REVISION`): the cost is once per shard per revision, not
  once per view. **That cache is load-bearing, not an
  optimization** — the note lives at the cache site as well as here,
  because a design doc does not defend a line of code from a cleanup
  PR.
- **512px / 1024px must be asynchronous with visible progress.** A
  25 s synchronous export on the floor device is **a hang, not a slow
  operation**. Blocking the UI at these sizes is a defect regardless
  of the budget.

#### Where the bound is enforced

A regression bound is only real if something re-runs it. Named
plainly, because "regression bound" otherwise implies automation that
does not exist:

- **(a) Named trigger, manual — the standing mechanism.** Any change
  in the **timed path** obliges a floor re-run before merge. The
  measured operation is `render_candidate_png_from_params` end to end
  — render *plus* PNG encode — so the trigger covers its whole call
  graph (renderers, compositor, palette, entropy draws, the encode
  path, and the imaging dependencies), not just the renderers: a
  subset would let a regression in through the part left out. Carried as a `docs/FOLLOWUPS.md` row
  with the trigger conditions written out. It relies on discipline —
  but so does every reopener in this program, and the alternative is
  pretending otherwise.
- **(b) Scheduled floor campaign — held in reserve**, as the
  escalation if (a) is observed failing, not the opening move.
- **(c) x86 smoke check in CI — taken, and muzzled.** CI runs the
  same matrix on x86 against separate, x86-derived thresholds. It
  catches gross regressions early and **cannot bound the floor** (see
  the sign-flipping ratios above), so the disclaimer rides in the
  gate's own **pass** line, not only on failure and not only in this
  document: a green line in CI reads as "performance is fine" to
  every human and every dashboard, and a paragraph three files away
  does not travel with the checkmark. The gate is named
  `shard-visual-x86-smoke` — not a budget or performance gate — so
  the name cannot overclaim either.

If a candidate algorithm can't hit the amended targets on the floor
device, it gets dropped from the palette or restricted to higher-end
rendering tiers.

### Reproducibility

The bar is **ruled** — see *Rendering determinism and empirical
closure (ruling B)* above. It is layered: hash-derived structure
(draws, palettes, opacities, the recipe) is bit-exact across platforms
and implementations; the painted raster is held to the pre-registered
perceptual metric (RGB-RMS ≤ θ = 2.0 against committed goldens,
decoded pixels never PNG bytes). "A human comparing two renderings
cannot distinguish them" is the intuition the metric operationalizes;
the metric, not the intuition, is what a conforming implementation is
tested against.

This means specifying:

- Iteration counts (Mandelbrot, attractors, reaction-diffusion)
- Color palette mappings (exact RGB values for each palette family)
- Resolution-independent parameter scaling (so 128x128 and 512x512
  renderings represent the same shard recognizably)
- Coordinate system conventions
- Rendering order for layered elements

A reference implementation in `shekyl-shard-visual` serves as the
canonical specification. Other implementations target visual
equivalence to the reference.

### Reorg behavior

When a shard's content changes due to a chain reorg, its visualization
changes too. The visual is a faithful function of current content; that
includes "current content after a reorg."

Stakers seeing "my shard looks different now" should be able to
understand it as "the chain reorganized — investigate."

**The ruled property is sensitivity, not continuity** (ruling B,
2026-09-05). An earlier version of this section promised that small
reorgs produce small visual changes; that text was wrong as written —
authored for the retired single-algorithm design and impossible under
candidate.v1's hash-seeded derivation, where any content change
avalanches the whole picture. And it asked for the wrong thing:
continuity and integrity-detection are in direct opposition here — a
rendering whose job is making corruption visible should change
maximally on any change, and a continuous rendering would have been a
silent-corruption hazard. Under sensitivity, visual change is a
binary signal: the picture changed, so the content changed; the
magnitude of the visual difference carries no information about the
size of the reorg. The per-algorithm "Continuity:" notes in the
fallback palette below are retained as historical assessment of the
fallback design only; they are not a requirement on candidate.v1.

---

## Privacy considerations

The earlier section noted that visualization parameters must be derived
from already-public properties. Worth being more specific about what
that means and the design-review checkpoint.

**Always safe to derive from:**

- Shard hash itself (already public, nothing additional revealed)
- Block count, transaction count (visible in any block explorer)
- Time range (block timestamps are public)
- Aggregate output count
- Coinbase-vs-transaction ratio (computable from any block explorer)

**Never derive from:**

- Specific transaction content
- Individual output values
- Wallet identifiers (addresses, view keys, etc.)
- Anything wallet privacy depends on

**Borderline cases — CLOSED by ruling A** (*Parameter admissibility*
above). The two cases this section held open resolved the opposite way
from its "probably fine" leanings, and for a reason the leanings could
not see: both assumed the underlying quantities were "computable from
any node anyway", which is true of the fake-chain corpus and false of
the real chain. Distribution moments of output values are **rejected**
(CT hides user output amounts — the moments are not computable from
held bytes at all); stake event ratios are **rejected for now** under
rule 21 (no ratified holder-readable stake-event surface exists yet;
the reopening criterion is named in the ruling).

**Design-review checkpoint — RUN (2026-09-04):** the checkpoint this
paragraph scheduled is ruling A's sweep. Its criterion is
pre-registered there; any change to the parameter set re-opens that
section, not this paragraph.

**Distinct concern — the *sharing behavior*, not the parameters.** The
analysis above establishes that the rendered visual leaks nothing the
chain doesn't already publish. A separate concern is that this feature
*exists to be shared* ("Print/share rendering," Open design questions),
so it manufactures a population of stakers who voluntarily reveal they
stake. That voluntary disclosure composes with the confidential-staking
**claim-cohort leak** (retired claim-era finding F0; living surfaces
`docs/design/PHASE_2B_FSM_RETOOL.md`, `docs/V3_STAKER_ARCHIVAL.md`): a
shared portfolio bridges real-world identity → "a staker
holding shard-set `{S}`," and — composed with F0's cleartext
`(tier, creation)` and a candidate on-chain holder registry
(`docs/V3_STAKER_ARCHIVAL.md`) — to that staker's claim cohort. The
elimination effect matters for the privacy-conscious minority: in a thin
cohort, self-doxxing by other members shrinks the silent members'
anonymity set. This is **not** a parameter-derivation issue (so it does
not change the "always safe / never derive from" lists), but it **is** a
real deanonymization vector that the archival/visualization privacy
review must weigh against claim-cohort linkage before ship. Tracked in
`docs/FOLLOWUPS.md` (pre-genesis residue, if any remains).

Two structural sharpenings make the sharing vector worse than "reveals
membership" (full analysis: `docs/V3_STAKER_ARCHIVAL.md` privacy
sections, finding **F-ARCHIVAL**):

- **A shared portfolio is a tier oracle.** Archival sorts tiers onto shard
  types (`docs/V3_STAKER_ARCHIVAL.md`: tier-1 → hot/recent, tier-3 →
  deep/historical), so *which shards a staker holds is strong evidence of
  their tier* — the same tier the confidential-staking claim wire reveals,
  re-exposed through portfolio composition. Sharing a portfolio therefore
  leaks tier, not just membership.
- **Rare = shareable = identifying.** "Legible rarity" gamifies showing off
  the rarest shard, which is by definition the *most* identifying (few others
  hold it), and rare-shard hunters skew toward larger, engaged stakers — the
  high-value targets. The feature's social appeal is mechanically a
  fingerprint disclosure, concentrated where it hurts most.

**Share-UX is a privacy surface (graceful-degradation requirement).** A user
who shares should disclose only *what they chose* — "I stake, here's cool
art" — and not have it silently cascade into tier, claim history, and
inferable amounts. The share/export path should **warn** that posting a
portfolio links social identity to staking history, and that the rarer the
shard, the more uniquely it identifies the holder. This is a V3.x share-UX
design item, gated with the archival commitment-binding decision.

**Resolution — the firewalled-pseudonym model achieves graceful degradation
(F-ARCHIVAL resolution; `docs/V3_STAKER_ARCHIVAL.md` §*Pay-for-service rebasing
and the firewalled-pseudonym identity model*).** The visualization **composes
cleanly** under the resolved model, which retroactively validates the
share-feature instinct. The image is shard-keyed and identical across holders,
so it does not identify the holder by itself; sharing it discloses "I am
pseudonym **P**, I hold these shards" — *the pseudonym's own public facts* — and
with the firewall in place (membership-proof binding, HKDF-separated identity,
network/timing/output isolation) that disclosure **does not cascade** to claims,
spends, principal, or tier. The two cascade-drivers above are closed at the
source: **tier** is neutralized by tier-neutral / longevity-based shard pricing
(so a portfolio is no longer a tier oracle), and the **claim-cohort bridge**
(F0) dissolves because the pay-for-service reward removes `tier`/`creation` from
the claim wire. Net: a sharer reveals exactly the pseudonym they chose to attach
to a social identity, and nothing behind it. The shared portfolio is still a
fingerprint *of P*, but fingerprinting a firewalled pseudonym only yields the
pseudonym the sharer already surfaced — the cost of sharing is **bounded to the
pseudonym**, which is the right place for a voluntary, social, opt-in feature to
spend privacy. The share-UX **warning still applies** (the disclosure is real, it
is just bounded), and the guarantee is contingent on the firewall holding across
all four layers and on the gate-list in `V3_STAKER_ARCHIVAL.md` ratifying.

---

## Implementation notes

### Where this lives in the codebase

The rendering layer lives in a separate library crate
(`shekyl-shard-visual`) so it can be reused outside the wallet (block
explorer, web portfolio views, future visualization-of-other-chain-
objects use cases — see "Beyond shards" below). The crate name is
locked as a domain-primitive crate name in
`docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 — `Wallet<S>` renamed to
`Engine<S>`* under "stays as-is" — domain primitives keep their
descriptive names rather than acquiring an `engine-` prefix.

The crate is **a library, not an actor.** Per the 2026-04-27 actor-
architecture decision-log entry, visualization is pure-CPU, async-
free, deterministic, and has no state to encapsulate or privacy
boundary to enforce. Wrapping it in an actor would add latency
(message-passing overhead on every thumbnail render), prevent reuse
in environments without a `kameo` runtime (block explorers, WASM web
portfolios), and conflate domain-primitive concerns with engine-
boundary concerns.

The crate is:

- **No-`std` compatible** for embedded / WASM use cases (with `std`
  feature for the desktop wallet)
- **Async-free** (rendering is pure CPU; no need for async)
- **Deterministic** (no system time, no thread-local random state;
  the raster's floating-point behaviour is governed by ruling B's
  layered bar, not by bit-exactness)
- ~~**Reproducible across platforms** (bit-equivalent output on x86,
  ARM, WASM)~~ — **retracted by ruling B (2026-09-05)**, struck rather
  than deleted so the reopening criterion travels with the claim: the
  shipped transcendental-float renderers cannot meet it, and the
  layered bar (structure bit-exact, raster perceptual) supersedes it.
  **Reopens if and only if a deterministic rasterizer is pinned across
  both implementations.**

~~Floating-point determinism is the technically hardest of these.
Different CPUs produce slightly different IEEE 754 results for some
operations. The rendering pipeline either uses fixed-point arithmetic
(cleanest) or constrains floating-point operations to those with
bit-exact cross-platform behavior.~~ *(Struck with the retraction
above; the ruled bar is in ruling B.)*

### Rendering output format

The natural output format is SVG (vector, scalable, deterministic) for
algorithms that produce vector content (Voronoi, L-systems,
phyllotaxis), and PNG (raster) for algorithms that produce continuous-
tone content (Mandelbrot, attractors, reaction-diffusion, flow fields).

A unified output type that wraps either could simplify the API:

```rust
pub enum ShardVisual {
    Vector(SvgDocument),
    Raster(PngImage),
}
```

The wallet UI consumes either, displays appropriately.

### Caching

Renderings are deterministic, so they're cacheable. A staker's wallet
holding 100 shards renders each once on first display, caches the
result, and re-renders only if the shard content changes (reorg).

Cache invalidation: keyed on (shard_id, shard_content_hash, and the
crate's exported `RENDER_REVISION`). The content hash changes on a
reorg; the revision changes when the pixel derivation itself changes
pre-freeze (review #617: a cache keyed without it can serve a stale
PNG alongside a recipe the current code would not produce). Once a
spec version freezes, a revision bump within it is a defect.

This makes the rendering performance budget less critical for
steady-state use — the user pays the cost once. But initial wallet-load
performance still matters; mobile users opening the app shouldn't wait
seconds for thumbnails.

---

## Beyond shards: visualization infrastructure as reusable layer

Once the visualization infrastructure exists, it can apply to other
chain objects. Worth flagging as future possibilities, *not* V3.x
ship scope:

- **Stake instances** — each stake gets a sigil derived from
  (stake_amount, lock_tier, lock_height, owner_view_tag). Stakers
  identify their stakes by appearance. Privacy-preserving because the
  derivation only uses information visible to the staker themselves
  (their own tag).
- **Block ranges, epochs, claim windows** — any deterministic chain
  object can have a visual identity. Block explorers use this for
  visual navigation.
- **Wallet identities** — derived from public address, displayed in
  the UI as a "engine sigil" (per the rename — internal terminology
  is "engine"; user-facing language for GUIs is a separate marketing
  decision, see `docs/V3_WALLET_DECISION_LOG.md` *2026-04-27 —
  `Wallet<S>` renamed to `Engine<S>`*). Privacy concern: the visual
  must reveal no more than the address itself does. Worth careful
  design if it ships.

These are post-V3-ship. The `shekyl-shard-visual` crate stays clean
enough to support them — generic enough that "render an X" works for
any X with a deterministic parameter mapping.

---

## V3-ship implications

This feature ships in V3.x alongside the V3.x `ArchivalEngine` Stage 5
ship. The mechanism is purely an addition layered on top of the V3.x
archival system. Visualizations are computed client-side from public
chain data; no consensus involvement, no new protocol surface, no new
RPC methods.

The dependencies and timing:

- **V3.0 ships without production visualization.** The
  `shekyl-shard-visual` crate exists and is integrated today, but only
  behind the pre-archival GUI preview (fixture aggregates on the
  Staking tab, per the preview exception above); no production shard
  surface renders visuals until `ArchivalEngine` (Stage 5) provides
  real shards.
- **V3.x ships `ArchivalEngine` (Stage 5) and `shekyl-shard-visual`
  together.** They are companion features: archival produces the
  shards; visualization makes them legible. Both gate on the
  simulation work described in `docs/V3_STAKER_ARCHIVAL.md`. Both
  ship in the same V3.x dot-release.
- **Existing shards in any earlier V3.x phase get visualizations
  retroactively.** Visualizations are derived from existing public
  data; activating the rendering layer in a later V3.x dot-release
  produces visuals for shards that already existed.

V3.0's design surface forecloses nothing here. The
domain-primitive crate name (`shekyl-shard-visual`) is pre-committed
in the rename entry's "stays as-is" list; the crate has no V3.0
dependency and is purely additive when V3.x activates it. The
no-tradeability enforcement-point inventory is codified above (*Not
tradeable*, "Concrete enforcement", verified 2026-09-04).

---

## Open design questions

These gate the V3.x ship dot-version. Each closes against design
review and performance testing during the V3.x implementation cycle.

**Final algorithm palette.** The **candidate.v1** two-stage difference
compositor (see above) is the leading design from empirical exploration.
Its determinism bar and the falsifiers for the closure are ruled
(*Rendering determinism and empirical closure (ruling B)*). The
measurement half — the floor-device budget matrix and the committed
goldens — was executed 2026-09-06 (*Measurements of record*); what
remains open is the ruling it forced, recorded under *Performance
targets*, and it was ruled 2026-09-06 (the budget gives). **This
question is CLOSED:** candidate.v1 is the palette, and the
single-algorithm fallback is retired — *Fallback disposition* under
*Candidate compositor*.

**Color palette specifications.** The exact RGB values for each palette
family. Candidates: hand-curated by a designer; algorithmically
generated (e.g., HSL rotations from a base hue); community-proposed.

**Parameter derivation function.** The exact mapping from
(shard_hash, content_properties) to (algorithm choice, algorithm
parameters, color palette). Needs design and privacy review.

**Mobile rendering strategy.** Mobile wallets running on phones have
much tighter performance budgets than desktop wallets. Strategy:
render at lower resolution on mobile, upscale for display? Render
server-side and cache on the wallet? Skip the most expensive
algorithms entirely on mobile? Worth deciding early since it affects
the palette choice.

**Print/share rendering.** When a staker wants to share their portfolio
publicly (Twitter screenshot, blog post, etc.), do they share at
native rendering quality or at higher quality? If higher: the
rendering pipeline supports a "high quality" mode for export. Worth
designing because it's the most likely user-facing edge case.

**Algorithm versioning.** If V3.x ships with palette V1 and a later
V3.x dot-release wants to add reaction-diffusion or change a color
palette, what happens to existing rendered shards? Two paths: (a)
shards always render with the algorithm version specified at chain
time (immutable); (b) shards re-render with the latest algorithm
(visual changes when wallet upgrades). Path (b) is simpler, path (a)
is more "true to the data." **Ruled on its privacy half** — path (a),
immutable render at the creation height — in *Spec version is chain data
(algorithm-versioning ruling)*. What remains is enforcement of the height
pin, blocked by name (rule 22) on Stage 5 creation heights: no height
exists for a fixture aggregate today.

---

## Conclusion

Shard visualizations turn an abstract economic mechanism (rare-shard
hunting) into a legible, distinctive, gamified experience without
introducing new economic dimensions or undermining privacy.

The mechanism is:

1. **Each shard has a deterministic visual** derived from its content.
2. **A palette of algorithms** (Mandelbrot, Voronoi, L-systems, etc.)
   ensures variety; algorithm assignment is hash-derived.
3. **Parameters come from public chain properties** — never from
   anything privacy-sensitive.
4. **Renderings are reproducible** across implementations, with a
   reference implementation in `shekyl-shard-visual` as canonical
   specification.
5. **No tradeability** — visualizations are not tokens, are not
   transferable, exist only as renderings of chain state. This is a
   hard architectural constraint that prevents introducing economic
   dimensions the V3 simulations didn't validate. Codification of the
   enforcement-point inventory codified in *Not tradeable* (verified
   2026-09-04).
6. **No NFT framing** in public communication — this is data art, not
   a separate asset class.
7. **Library crate, not actor.** `shekyl-shard-visual` is a domain-
   primitive library: pure-CPU, async-free, deterministic, reusable
   outside the wallet. The 2026-04-27 actor-architecture decision pins
   library-shape as the correct one for visualization (no state, no
   privacy boundary, synchronous nature, multiple consumers).

The structural innovation: **deterministic visual identity for chain
state, decoupled from any tradeable asset.** Prior crypto-art systems
have either been off-chain images with on-chain pointers (NFTs) or
on-chain procedural art with speculative trading (Art Blocks et al.).
This is on-chain data with on-chain visualization, with deliberately
*no* trading mechanism. The visual exists to make data legible, full
stop.

V3.x ships this alongside `docs/V3_STAKER_ARCHIVAL.md`. Together they
make archival economically incentivized, distributed, and culturally
resonant — the "real work" stakers perform becomes visible, both in
the metaphorical sense (the network values it) and the literal sense
(stakers see their portfolios). V3.0 ships the architectural surface
that makes V3.x activation purely additive (rename entry pre-commits
the `shekyl-shard-visual` crate name; the no-tradeability
enforcement-point inventory is codified in *Not tradeable*).

---

## References and cross-cutting concerns

- `docs/V3_STAKER_ARCHIVAL.md` — the archival mechanism this layer
  visualizes (companion document, ships together in V3.x)
- `docs/V3_WALLET_DECISION_LOG.md` — *2026-04-27 — Engine architecture:
  actor model with staged migration from composition* (pin of
  `shekyl-shard-visual` as library crate, not actor); *2026-04-27 —
  `Wallet<S>` renamed to `Engine<S>`* ("stays as-is" pre-commit of
  the crate name)
- `docs/FOLLOWUPS.md` — V3.x *Stage 5 ArchivalEngine native build*
  (companion archival ship); the no-tradeability enforcement-point
  inventory closed 2026-09-04 (codified in *Not tradeable* above)
- `docs/DESIGN_CONCEPTS.md` — V3 economic structure (the model this
  must not undermine)
- Future: `docs/PUBLIC_NARRATIVE_FAQ.md` — should grow a "shard
  visualization FAQ" section addressing the inevitable "are these
  NFTs?" questions

### External references for visualization algorithms

- Mandelbrot set: <https://en.wikipedia.org/wiki/Mandelbrot_set>
- Julia set: <https://en.wikipedia.org/wiki/Julia_set>
- Voronoi diagram: <https://en.wikipedia.org/wiki/Voronoi_diagram>
- L-system: <https://en.wikipedia.org/wiki/L-system>
- Lorenz system: <https://en.wikipedia.org/wiki/Lorenz_system>
- List of chaotic maps: <https://en.wikipedia.org/wiki/List_of_chaotic_maps>
- Reaction-diffusion system:
  <https://en.wikipedia.org/wiki/Reaction%E2%80%93diffusion_system>
- Turing pattern: <https://en.wikipedia.org/wiki/Turing_pattern>
- Phyllotaxis: <https://en.wikipedia.org/wiki/Phyllotaxis>
- Perlin noise (for flow fields):
  <https://en.wikipedia.org/wiki/Perlin_noise>
