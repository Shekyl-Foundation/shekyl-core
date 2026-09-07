# Shard-visual — the items ruling B was assigned and never closed

**Status:** Design round 1, awaiting ruling. Companion to
[`docs/V3_SHARD_VISUALIZATION.md`](../V3_SHARD_VISUALIZATION.md).
Nothing here is implemented; every item changes pixels, and the cost of
that is stated with each one.

---

## First: the item that does not exist

A roster row circulated describing a remaining ruling-B half — "layered
bar / θ-sensitivity re-render, ratified 2026-09-05, never executed."
**No such item exists.** Ruling B ratified exactly three questions (the
layered determinism bar, the sensitivity reframe, and the floor-device
measurement), and PR #631 executed all three; it merged 2026-09-06 as
`286e12598`.

The claim originated with me, in a lane-memory line written while
closing the very lane that executed those three questions, and it
propagated from there into a message, a roster row, and back as an
instruction. It is corrected at both memory sites. Recorded here
because the same document would otherwise be read as evidence for it.

What follows is what the **spec itself** assigns to ruling B, by name,
and ruling B did not close. Each is grounded in a quoted line, not in
recollection.

---

## Item 1 — `time_density`: admitted, and consumed by nothing

*Parameter admissibility (ruling A)*, sweep table:

> `time_density` | **ADMIT** | block timestamps are in held block bytes
> (currently unconsumed by candidate.v1; **whether it drives aesthetics
> is ruling B's call**)

**Verified against the code, not assumed.** In the Rust crate
`time_density` is computed in `features.rs` and read by no renderer;
the other three admitted features are each consumed
(`activity_density` and `coinbase_ratio` by `crystalline`,
`coinbase_ratio` by `truchet`, `output_richness` by `truchet`,
`phyllotaxis`, and `aperiodic_tile`). The Python explorer matches: it
computes `time_density` in `parameters.py` and no renderer reads it.

So the field is a **correct mechanism with no consumer** — it survives
in both implementations, in the KAT'd feature vector, and in every
`Features` construction, while contributing nothing to any pixel.

**Options.**

- **(a) Consume it.** Gives the fourth admitted feature a job and makes
  shards with identical counts but different time spans render
  differently. Cost is the full cascade in §*What any pixel change
  costs* below.
- **(b) Delete it from `Features`.** An admitted-but-unused field is
  debt in the sense rule 15 means: it reads as load-bearing to the next
  maintainer. Deleting is cheap *now* and expensive later — it is a
  wire-shape change to a KAT'd struct.
- **(c) Keep it dormant, with a rule-21 reopening criterion** naming
  what would make it consumed.

**Recommendation: (b), delete it — with (a) as the argued alternative.**
The admissibility ruling establishes that it *may* be used, not that it
*should* be; nothing in the design wants a time axis today, and the
honest way to hold "we may want this later" is a named reopening
criterion plus a one-line git history, not a field that every reader
must infer is inert. If the aesthetics work in Item 2 gives the visuals
a reason to want a time axis, (a) becomes the better answer and this
should be decided **after** Item 2, not before.

---

## Item 2 — the post-rewire aesthetics

*Parameter admissibility (ruling A)*, closing line of the sweep:

> Renderer inputs that consumed rejected features now draw from the
> renderer's own SHAKE256 structural namespace at previously-unused
> indices … **the resulting aesthetics are ruling B's to close.**

Ruling A removed the privacy leak by rewiring several renderer inputs
from real features to hash draws. Nobody has since looked at what the
pictures became. Evidence is attached to this round (nine fixtures at
512px, and the same nine at the 128px thumbnail size). Three findings,
in descending order of how much they matter:

**2a. At 128px — the actual product surface — distinguishability is
materially weaker than at 512px.** The spec's palette requirements ask
that shards be "visually distinct … so two shards using the same
algorithm but different palettes look clearly different". At 512px all
nine are obviously distinct. At 128px, `genesis`, `drain_burst`,
`active`, `stake_heavy`, and `whale` collapse toward similar muted
purple/mauve mid-tones; fine structure averages away and colour is left
carrying the entire discriminating load. This bears directly on
property 1 (the visual integrity check), which is a **thumbnail**
affordance: two holders comparing shards at portfolio size is the use
case, and that is the size where the design is weakest.

**2b. Composition is invariant across the corpus.** Every shard is a
centred circular medallion on a blobby ground — a structural
consequence of the fixed pipeline (radial `phyllotaxis`/`aperiodic_tile`
foreground ⊖ `truchet`/`crystalline` background). Shards vary in colour
and texture but never in layout. This is not a defect; it is a
recognisable house style, and it may be exactly what is wanted. It is
called out because it is invisible until the corpus is seen side by
side, and because it is the main lever available for 2a.

**2c. The `crystalline` layer contributes a single bright horizontal
line, not the structure its own documentation describes.** Every
fixture shows one anomalous scanline at a hash-derived height (measured:
3.0×–3.6× the median row residual, at y=332/315/325/283 for
genesis/drain_burst/stake_heavy/quiet at 512px).

The Rust port is **faithful** — the Python reference does the same
thing (`ys = np.full_like(theta, K / 2.0)`, a constant), and its
docstring calls it "a horizontal scatter". So this is not the ported-
renderer divergence class that round 3 of #617 found. But the same
docstring says:

> The crystalline aesthetic comes from the Arnold-tongue structure of
> stable rotation numbers showing as bright vertical bands.

A circle-map orbit plotted at constant `y` cannot show Arnold tongues.
Tongue structure appears when the *parameter* (`K` or `omega`) is swept
along one axis and the orbit along the other; with `y` held constant the
2D diagram collapses to one line. **The reference implements something
other than what it describes**, and the Rust crate faithfully reproduces
the something-other. Whether to fix that is a ruling, because it changes
pixels.

---

## Item 3 — fallback disposition / "formal palette closure"

*Candidate compositor*:

> This pipeline is the **leading design** … **pending formal palette
> closure** … The single-algorithm palette in the sections below remains
> the **fallback spec shape** if candidate.v1 fails mobile budget or
> continuity review; disposition closes during V3.x implementation.

**Both trigger conditions have now been resolved, which makes this
decidable for the first time.** Continuity was ruled (it was the wrong
property; sensitivity replaced it). The mobile budget was measured on
the floor device — candidate.v1 missed every cell — and the ruling was
that *the budget gives*, not the candidate. So the fallback's condition
("if candidate.v1 fails review") did not fire in the sense that
mattered: candidate.v1 stands.

**Recommendation: retire the single-algorithm fallback explicitly**, by
the archive-or-contract discipline of rule 95, rather than leaving it as
a standing alternative nobody intends to build. A documented fallback
that no longer has a trigger is a second design the next maintainer
must keep reading and reconciling. If it is retired, the reopening
criterion should be named (rule 21) — the obvious one being a future
floor-device measurement that candidate.v1 cannot be made to satisfy.

---

## Stale entry found while censusing (no ruling needed, just a fix)

*Open design questions* still lists **Algorithm versioning** as fully
open — "Worth thinking about; closes during V3.x design review" — while
*Spec version is chain data (algorithm-versioning ruling)* has already
ruled its privacy half (path (a), immutable render at creation height),
with enforcement blocked on Stage 5 creation heights under rule 22. The
open-questions entry should point at the ruling and carry the named
blocker. This is the status-claim-spreads-to-every-surface class; it
lands with whatever ruling this round produces.

---

## What any pixel change costs

Stated once, because it applies to Items 1(a), 2, and 2c alike, and
because the enforcement was built in #631 specifically so this cannot
be done quietly:

1. `RENDER_REVISION` must be bumped (`src/lib.rs`), or CI's
   `shard-visual-x86-smoke`-adjacent gate
   `scripts/ci/check_golden_revision_bump.py` fails the PR — a modified
   golden PNG without a revision change is a hard error.
2. The nine goldens regenerate from a clean tree, and the artifact's
   `_reference_run` must record `dirty: false`.
3. The twin Python KAT's copy of `recipes.json` must be regenerated in
   `shekyl-dev` if any recipe field moves (a pure raster change does not
   move recipes).
4. The floor re-run trigger fires: the change is inside the timed path,
   so a fresh `skl-pi` budget matrix is owed before merge, with its
   capture committed under `docs/benchmarks/`.
5. The GUI wallet's cached previews invalidate by `cache_digest`, which
   is the intended behaviour and needs no wallet change.

This is not an argument against changing pixels. It is the price list,
so a ruling is made knowing it.

---

## The ask

1. **Item 1** — `time_density`: delete (recommended), consume, or hold
   dormant with a named reopening criterion. Best decided after Item 2.
2. **Item 2** — the aesthetics: accept as they stand, or open a
   follow-up to improve 128px distinguishability (2a) and/or make
   `crystalline` deliver the structure it documents (2c). 2b is
   reported for awareness, not decision.
3. **Item 3** — retire the single-algorithm fallback with a named
   reopening criterion (recommended), or keep it and say what would now
   trigger it.

None of these is urgent and none blocks anything shipped. They are
recorded so that ruling B's assigned residue is closed deliberately
rather than forgotten — which is the failure this round exists to
prevent, having just demonstrated the cost of a status claim nobody
re-grounded.
