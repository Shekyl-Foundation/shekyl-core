# V4 Design Notes — Shard Visualization (Visual Identity Layer)

**Status:** Design exploration, V4-scoped. Companion to
`V4_STAKER_ARCHIVAL.md`. The archival mechanism functions without
this; this layer makes archival legible to humans.

**Author / decision context:** Emerged in Phase 1 wallet-rewrite session
(2026-04-26) while exploring gamification of the shard archival
mechanism. The Pokemon analogy ("gotta collect 'em all") and the
Mandelbrot reference led to the realization that *deterministic visual
identity for chain state* is structurally meaningful, not just eye
candy.

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
load-bearing for the V3/V4 economic model.

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
become invalid. The V3-V4 economic model breaks.

This is the same class of failure mode as Ethereum's "add features
and figure out consequences later" pattern. Each addition looks
harmless in isolation; the cumulative effect is an economy nobody
designed.

**The discipline: visualizations exist because they make archival
legible, and for no other reason.** Anything that turns them into a
separate economic asset breaks the model.

Concrete enforcement:

- Wallet UI has no "trade" button on shard visuals
- No wire format for transferring shard visual ownership
- No on-chain registry of who "owns" a visual
- Anyone running an archival client can render any shard's visual at
  any time (no scarcity of *rendering*; scarcity is in *active
  archival*)

If a community proposal in V4.x or beyond suggests adding tradeability,
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
with explicit "no, here's why" answers. That FAQ is a Phase 4b or V4
shipping concern, not a design-doc concern, but worth flagging that
the communication needs care.

---

## The mechanism

### Parameter derivation

Each shard's visualization is parameterized by characteristics derived
from the shard's content. Critically, **parameters are derived from
properties that are already public** — never from anything that wallet
privacy depends on.

Candidate derived properties (all public, all computable by anyone
holding the shard):

- Shard hash (256 bits, uniformly distributed)
- Block count in shard
- Transaction count (aggregate)
- Time range (first block timestamp to last block timestamp)
- Output count (number of new outputs created in the shard's block range)
- Stake event count (stakes created, stakes claimed)
- Distribution moments of output values (mean, variance — aggregate
  statistics only, not individual values)
- Coinbase ratio (proportion of outputs from miner emission vs. user
  transactions)

These are aggregate, public, and chain-derived. None of them leak
individual transaction information or undermine FCMP++'s privacy
properties. Worth verifying explicitly during V4 implementation that
the chosen parameter set doesn't accidentally encode anything sensitive
— this is a design-review checkpoint.

The shard hash provides the bulk of the "uniqueness" entropy. The
content-derived properties make the visual *say something true* about
the shard rather than being a pure hash visualization. A shard from a
high-activity chain period looks visibly different from a quiet-period
shard; experienced stakers learn to read this.

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

## Rendering discipline

### Performance targets

- **Mobile wallet thumbnail (128x128):** sub-50ms render
- **Desktop wallet portfolio view (256x256):** sub-100ms render
- **Detail view (512x512):** sub-300ms render
- **Print-quality / share image (1024x1024):** sub-2s render

If a candidate algorithm can't hit these on the target devices, it
gets dropped from the palette or restricted to higher-end rendering
tiers. Mobile users seeing portfolio views at 128x128 must not have
a slow experience.

### Reproducibility

The rendering specification must be tight enough that any conforming
implementation produces *visually equivalent* output. Pixel-perfect
equivalence is overkill for the use case (visual identity / integrity
check); the bar is "a human comparing two renderings cannot
distinguish them."

This means specifying:

- Iteration counts (Mandelbrot, attractors, reaction-diffusion)
- Color palette mappings (exact RGB values for each palette family)
- Resolution-independent parameter scaling (so 128x128 and 512x512
  renderings represent the same shard recognizably)
- Coordinate system conventions
- Rendering order for layered elements

A reference implementation in the wallet codebase serves as the
canonical specification. Other implementations target visual
equivalence to the reference.

### Reorg behavior

When a shard's content changes due to a chain reorg, its visualization
changes too. The visual is a faithful function of current content; that
includes "current content after a reorg."

Stakers seeing "my shard looks different now" should be able to
understand it as "the chain reorganized." Small reorgs should produce
small visual changes (continuous-function property of the chosen
algorithms); large reorgs produce larger visual changes.

This is a useful property: visual change *is itself a signal* of chain
events. A staker noticing a sudden visual shift might investigate and
discover a reorg they otherwise wouldn't have noticed.

The continuity-of-rendering requirement excludes algorithms with high
sensitivity to small parameter changes. L-systems are the riskiest in
this regard; they should be tested for continuity before inclusion in
the palette.

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

**Borderline cases requiring review:**

- Distribution moments of output values: aggregate statistics, but
  could in principle leak macro-information about chain activity
  patterns. Probably fine for V4 since this information is computable
  from any node anyway, but worth verifying.
- Stake event ratios: same shape — aggregate, but encodes
  macro-economic information. Probably fine.

**Design-review checkpoint:** before V4 ships, the chosen parameter
derivation function gets reviewed for "does any of this leak
information that the chain protects elsewhere?" If yes, that
parameter is dropped. If no, it ships.

The default should be conservative: start with shard hash + block
count + time range only, add other parameters only if they pass
review. This is safer than starting rich and trimming.

---

## Implementation notes

### Where this lives in the codebase

The rendering layer should be a separate crate (e.g.,
`shekyl-shard-visual`) so it can be reused outside the wallet (block
explorer, web portfolio views, future visualization-of-other-chain-
objects use cases — see "Beyond shards" below).

The crate should be:

- **No-`std` compatible** for embedded / WASM use cases (with `std`
  feature for the desktop wallet)
- **Async-free** (rendering is pure CPU; no need for async)
- **Deterministic** (no system time, no thread-local random state, no
  floating-point operations whose result depends on hardware)
- **Reproducible across platforms** (bit-equivalent output on x86,
  ARM, WASM)

Floating-point determinism is the technically hardest of these.
Different CPUs produce slightly different IEEE 754 results for some
operations. The rendering pipeline should either use fixed-point
arithmetic (cleanest) or constrain floating-point operations to
those with bit-exact cross-platform behavior.

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

Cache invalidation: keyed on (shard_id, shard_content_hash). When the
content hash changes, the cached render is invalidated.

This makes the rendering performance budget less critical for
steady-state use — the user pays the cost once. But initial wallet-load
performance still matters; mobile users opening the app shouldn't wait
seconds for thumbnails.

---

## Beyond shards: visualization infrastructure as reusable layer

Once the visualization infrastructure exists, it can apply to other
chain objects. Worth flagging as future possibilities, *not* V4
scope:

- **Stake instances** — each stake gets a sigil derived from
  (stake_amount, lock_tier, lock_height, owner_view_tag). Stakers
  identify their stakes by appearance. Privacy-preserving because the
  derivation only uses information visible to the staker themselves
  (their own tag).
- **Block ranges, epochs, claim windows** — any deterministic chain
  object can have a visual identity. Block explorers use this for
  visual navigation.
- **Wallet identities** — derived from public address, displayed in
  the UI as a "wallet sigil." Privacy concern: the visual must reveal
  no more than the address itself does. Worth careful design if it
  ships.

These are post-V4. Worth keeping the rendering crate clean enough to
support them — generic enough that "render an X" works for any X with
a deterministic parameter mapping.

---

## V3 forecloses nothing here

This feature requires no V3 changes. The mechanism is purely an
addition layered on top of the V4 archival system. Visualizations are
computed client-side from public chain data; no consensus involvement,
no new protocol surface, no new RPC methods.

The only V4 dependency is on V4 archival itself: visualizations are
*for shards*, and shards exist because of archival. Without archival,
there are no shards to visualize. Both ship together in V4.

V3 ships without any visualization machinery. V3 wallets render shards
as plain hash strings or "Shard #4712" text labels. V4 wallets upgrade
the rendering layer to produce visuals. Existing shards in the V3
archival mechanism (if any — see V4_STAKER_ARCHIVAL.md bootstrap
dynamics) get visualizations retroactively when V4 ships, since the
visualizations are derived from existing public data.

---

## Open design questions

Not blockers; next-steps if this direction proceeds.

**Final algorithm palette.** The candidate list above is a starting
set; the actual palette ships after performance testing and continuity
review. Some candidates may drop; others may be added.

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

**Algorithm versioning.** If V4 ships with palette V1 and V4.1 wants
to add reaction-diffusion or change a color palette, what happens to
existing rendered shards? Two paths: (a) shards always render with the
algorithm version specified at chain time (immutable); (b) shards
re-render with the latest algorithm (visual changes when wallet
upgrades). Path (b) is simpler, path (a) is more "true to the data."
Worth thinking about.

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
   reference implementation as canonical specification.
5. **No tradeability** — visualizations are not tokens, are not
   transferable, exist only as renderings of chain state. This is a
   hard architectural constraint that prevents introducing economic
   dimensions the V3/V4 simulations didn't validate.
6. **No NFT framing** in public communication — this is data art, not
   a separate asset class.

The structural innovation: **deterministic visual identity for chain
state, decoupled from any tradeable asset.** Prior crypto-art systems
have either been off-chain images with on-chain pointers (NFTs) or
on-chain procedural art with speculative trading (Art Blocks et al.).
This is on-chain data with on-chain visualization, with deliberately
*no* trading mechanism. The visual exists to make data legible, full
stop.

V4 ships this alongside `V4_STAKER_ARCHIVAL.md`. Together they make
archival economically incentivized, distributed, and culturally
resonant — the "real work" stakers perform becomes visible, both in
the metaphorical sense (the network values it) and the literal sense
(stakers see their portfolios).

---

## References and cross-cutting concerns

- `V4_STAKER_ARCHIVAL.md` — the archival mechanism this layer
  visualizes
- `docs/DESIGN_CONCEPTS.md` — V3 economic structure (the model this
  must not undermine)
- `docs/V3_WALLET_DECISION_LOG.md` — Phase 1 decision context
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
