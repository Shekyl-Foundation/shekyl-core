# Shekyl's Modified Merkle Tree: How FCMP++ Works

> **Last updated:** 2026-04-05

## The Big Idea

**"Prove your money exists in the entire history… without anyone knowing which one is yours"**

In a normal blockchain, proving "I own this coin" is easy — the ledger literally lists who owns what. But that kills privacy. Shekyl (like Monero) wants **full anonymity**: every output should blend into the entire history of the chain so no one can tell which specific coin you are spending.

The solution is a **membership proof**: prove "my output is somewhere in the giant list of all outputs ever created" without revealing *where* it is.

A plain Merkle tree (the classic blockchain structure) lets you prove "this thing is in the list" efficiently, but it doesn't hide *which* thing it is, and it doesn't support the fancy math needed for zero-knowledge (ZK) proofs. So we **modify** the Merkle tree to make it work with zero-knowledge proofs while adding our post-quantum (PQC) binding.

---

## The Output Tuple: What Goes Into a Leaf

Every time someone receives SHEKYL, the transaction creates an "output" — basically a locked piece of money on the chain. That output contains four pieces of data:

**O** — the output key. This is essentially "who can spend this money." It's a point on the Ed25519 elliptic curve.

**I** — the key image generator. This is derived deterministically from O via `HashToPoint(O)`. It exists so that when you spend the output, you can produce a unique "key image" that prevents double-spending without revealing which output you spent.

**C** — the commitment. This is a Pedersen commitment that hides the amount of SHEKYL. It lets the network verify "inputs equal outputs" (no money created from nothing) without anyone seeing the actual amounts.

**H(pqc_pk)** — *our addition*. This is a hash of the per-output post-quantum public key. It binds the quantum-resistant authorization key to the output inside the tree, so the FCMP++ proof simultaneously proves "this output exists" and "this PQC key belongs to it."

Now, elliptic curve points are pairs of coordinates (x, y). But a key insight in the FCMP++ design is that you only need the x-coordinate to uniquely identify a point (up to sign — there are two points with the same x, one "positive" and one "negative"). The spec says: store only the x-coordinates. So each output becomes three field elements (numbers in a specific finite field): `O.x`, `I.x`, `C.x`. We add a fourth: `H(pqc_pk)`, which is already a scalar (a 32-byte number).

That's one leaf tuple: **4 numbers, each 32 bytes, totaling 128 bytes per output.**

### Why only the x-coordinate?

Imagine a clock face. If you tell someone "the hand points at position 3 on the x-axis," there are only two possible positions: 3 o'clock and 9 o'clock (one "above" the center, one "below"). With elliptic curves, it's the same — an x-coordinate maps to exactly two possible points. Since the prover knows which one they mean, and the proof can handle the ambiguity (by proving for either the point or its negation), storing just x saves 32 bytes per field per output with no loss of security.

This also has a subtle consequence for key images. Since `O.x` and `(−O).x` are the same number, the proof can't distinguish between `O` and `−O`. This means linking tags (key images) are redefined as x-coordinates only — the sign bit is cleared via `key_image_y()` normalization.

---

## The Flat Leaf Array: Outputs Laid End to End

The tree doesn't store leaves in separate buckets. It lays all the leaf scalars out in one flat array:

```
Output 0              Output 1              Output 2
[O.x, I.x, C.x, H]   [O.x, I.x, C.x, H]   [O.x, I.x, C.x, H]  ...
```

This is where the "6-scalar" confusion likely came from — if you're looking at Monero's version (3 scalars per output) and you see two outputs next to each other, you see 6 numbers in a row and might think that's one unit.

### A source of confusion: leaf width vs circuit internals

Inside the zero-knowledge circuit code, the prover works with full (x, y) coordinate pairs for each elliptic curve point — because the circuit needs to verify that points actually lie on the curve and perform blinding operations. So in the code, you'll see something like `[O.x, O.y, I.x, I.y, C.x, C.y]` — that's 6 values for Monero's 3 points. But these are **circuit-internal variables**, not stored data. The tree itself only stores the x-coordinates. Someone reading the prover code sees "6" and thinks that's the leaf width. It's not — it's the circuit's internal representation of 3 points as 6 coordinates.

For Shekyl, the circuit will work with `[O.x, O.y, I.x, I.y, C.x, C.y, H(pqc_pk)]` — 7 internal values representing our 4 leaf scalars. The on-chain leaf tuple is still 4 scalars. The circuit just needs the extra y-coordinates to do its internal math.

---

## Chunking: Grouping Scalars for Hashing

The tree doesn't hash all the scalars at once. It groups them into **chunks** — think of it like pages in a book. The chunk size (also called the branching factor or "width") determines how many scalars get combined in one hash operation.

Say the chunk width is 2 outputs. In Monero, that's 2 × 3 = 6 scalars per chunk. In Shekyl, that's 2 × 4 = 8 scalars per chunk. The hash combines all the scalars in one chunk into a single output point.

```
Chunk 0 (outputs 0-1)                          Chunk 1 (outputs 2-3)
[O.x, I.x, C.x, H, O.x, I.x, C.x, H]         [O.x, I.x, C.x, H, O.x, I.x, C.x, H]
                  ↓                                               ↓
            Selene Point₀                                   Selene Point₁
```

### Actual chunk sizes in FCMP++

The real branching factors are much larger than 2. The current parameters are:

- **Layer 0 (leaf → Selene):** `LAYER_ONE_LEN = 38` outputs per chunk. That means 38 × 4 = 152 Selene scalars per Pedersen hash (Monero: 38 × 3 = 114).
- **Layer 1+ (Selene → Helios or Helios → Selene):** `LAYER_TWO_LEN = 18` children per chunk.

Larger chunks mean a shallower tree (fewer layers to prove through), which makes proofs smaller and faster. But larger chunks also mean larger Pedersen commitments (more curve multiplications per hash). The 38/18 split is the balance point chosen by the FCMP++ designers.

With these branching factors, a tree holding 100 million outputs would have roughly 5-6 layers — meaning the proof traverses 5-6 levels from leaf to root. Each layer adds a constant amount to the proof size, so the proof grows logarithmically with the number of outputs: doubling the UTXO set adds about one more layer, not double the proof.

---

## The Hash: Pedersen Vector Commitments

Here's where it gets interesting. The "hash" used is not SHA-256 or any conventional hash. It's a **Pedersen vector commitment** — a cryptographic construction where you multiply each scalar by a different, publicly known "generator point" on the curve, then add the results together.

Think of it like a weighted sum, but with elliptic curve points instead of regular numbers:

```
Hash = scalar₁ × G₁ + scalar₂ × G₂ + scalar₃ × G₃ + scalar₄ × G₄ + ...
```

Each `G` is a fixed, publicly known point (a "generator"). Each scalar is one of our leaf values. The result is a new point on the curve.

### Why Pedersen instead of SHA-256?

Because Pedersen commitments are **additively homomorphic** — you can do math on the committed values without opening them. This is what makes the zero-knowledge proof work.

Here's an analogy. Imagine you have a locked safe with a dial that shows a number. You can add to the number on the dial from outside (by turning it), but you can't see what's inside. If two people each put a number in, you can verify from outside that "the sum is correct" without ever opening the safe.

Pedersen commitments work like this. The prover can show "I know which leaf is mine" without revealing which one, because the proof operates on the algebraic structure of the commitments rather than on raw data. A conventional hash like SHA-256 would destroy that algebraic structure — it's like grinding the safe into powder. You can verify the powder came from a safe, but you can't do any math with it anymore.

The cost of this: Pedersen hashing is much more expensive than SHA-256 (it's elliptic curve multiplication), and each additional scalar in the leaf means one more curve multiplication per hash. That's why our 4th scalar isn't free — it adds one more `scalar × Generator` operation to every leaf-layer hash in the tree.

### Blinding: why randomness is added

The raw Pedersen hash of a chunk is deterministic — the same leaf values always produce the same point. That would be a problem for zero-knowledge: if someone knows what the leaves are (they're on the public blockchain), they can recompute the hash and learn which path you're proving.

The solution is **blinding**: the prover adds a random "blinding factor" to each layer's Pedersen commitment. This is like adding a secret random offset — it shifts the output point to a random-looking location that still satisfies the mathematical relationships the proof needs, but reveals nothing about which specific inputs were used.

```
Blinded_Hash = scalar₁ × G₁ + scalar₂ × G₂ + ... + blinding_factor × T
```

Where `T` is yet another generator point dedicated to blinding. The verifier never sees the blinding factor — they only see the blinded commitment, which looks random. The proof demonstrates that the blinding was done correctly (the unblinded value is a valid chunk hash) without revealing the blinding factor or the specific leaf.

Each layer of the tree gets independently blinded during proof generation. The final (top) layer uses `blinding = 0` so the output matches the public tree root.

---

## The Tower Cycle: Why Two Curves?

Here's the subtlest part. A Pedersen commitment takes scalars as input and produces a **point** as output. But a point lives in a different mathematical space than a scalar. Specifically, a point's coordinates are elements of the curve's "base field," while scalars are elements of the curve's "scalar field." These are different-sized number systems.

To build a multi-layer tree, the output of one layer's hash needs to become the input to the next layer's hash. But the output is a point (base field), and the input needs to be a scalar (scalar field). You can't directly feed one into the other.

### The analogy: metric and imperial

Think of it like measuring a room in meters, but the door dimensions are only available in feet. You can't just plug 3 meters into a formula that expects feet — you need a conversion. But what if the conversion factor itself changes depending on which unit system you're in? Now you're stuck in a loop.

The curve cycle solves this. It's like finding two measurement systems where "1 unit in system A" equals "1 unit in system B's reference frame," and vice versa — so you can freely convert back and forth without any loss or ambiguity.

### Selene and Helios

The FCMP++ design uses two curves:

- **Selene** — the first curve
- **Helios** — the second curve

These are specifically constructed so that a Selene point's coordinates are valid Helios scalars, and a Helios point's coordinates are valid Selene scalars. The tree alternates between them:

```
Leaf scalars (Selene field elements)
    ↓ Pedersen hash with Selene generators
Layer 0: Selene points
    ↓ take x-coordinate of each Selene point → valid Helios scalar
    ↓ Pedersen hash with Helios generators
Layer 1: Helios points
    ↓ take x-coordinate of each Helios point → valid Selene scalar
    ↓ Pedersen hash with Selene generators
Layer 2: Selene points
    ↓ ...continues alternating...
Root
```

This is the "tower cycle" — it towers over Ed25519 (the base curve that Monero/Shekyl outputs live on). Wei25519 (a Weierstrass representation of the same underlying curve as Ed25519) sits at the bottom. Selene sits on top of it (its scalar field matches Ed25519's base field), and Helios pairs with Selene to form the cycle.

### Why not just use one curve?

A single curve can't cycle with itself — its base field and scalar field are different-sized prime numbers (that's a fundamental property of elliptic curves). You need a partner curve. And finding a pair where the fields match up perfectly is non-trivial — tevador (a Monero researcher) found the Helios/Selene pair specifically for this purpose.

Also, a curve cycle directly with Ed25519 is impossible because Ed25519 has a cofactor of 8 (it's not prime-order). Selene is a prime-order curve that "towers" over Ed25519 — it can represent Ed25519 points in its scalar field, but it doesn't inherit Ed25519's cofactor problem.

---

## The Tree is Append-Only

A critical property: **spent outputs are never removed from the tree.** The tree only grows — new outputs are appended, and old outputs stay forever.

Why? Because removing a spent output would reveal *which* output was spent. If you see leaf #42 disappear from the tree, you know someone just spent output #42. That completely defeats the privacy goal.

This means the tree grows monotonically with the output set. At 100 million outputs, the leaf data alone is ~12.8 GB (100M × 128 bytes). The internal hash layers add some overhead, but it's bounded: the tree depth grows logarithmically, not linearly.

### Implications for nodes

- **Full archival nodes** store the complete tree (leaves + all internal hash layers)
- **Pruned nodes** can discard intermediate hash layers between checkpoints — they keep all leaves (needed to rebuild paths) and checkpoint snapshots (for fast-sync), but drop the internal hashes that can be recomputed
- **Fast-sync nodes** download a recent checkpoint (a snapshot of the full tree state at a specific block height), verify it matches the tree root committed in the block header, then replay blocks forward

---

## Deferred Insertion: When Outputs Enter the Tree

Not every output enters the tree immediately. Shekyl uses **deferred insertion** — each output gets an "eligible height" that determines when it becomes part of the tree.

| Output type | When it enters the tree |
|---|---|
| Regular transaction output | 10 blocks after creation (~20 minutes) |
| Coinbase (mining reward) | 60 blocks after creation (~2 hours) |
| Staked output | At `lock_until` (when the stake lock expires) |

Outputs waiting to mature sit in a "pending" table. When the blockchain reaches their eligible height, they are drained from pending into the tree in a deterministic order (sorted by eligible height, then by global output index). This guarantees all nodes build identical trees.

### Why defer insertion?

Three reasons, all security-related:

First, **coinbase maturity.** Mining rewards must wait 60 blocks before they can be spent — this is inherited from CryptoNote and prevents issues if a mined block gets orphaned in a reorganization. Without deferred insertion, a coinbase output would be in the tree immediately, and someone could construct an FCMP++ proof referencing it. If the block then gets orphaned, the proof references an output that no longer exists. Deferred insertion prevents this — the output isn't in the tree until it's confirmed beyond the maturity window.

Second, **staking lock enforcement.** Staked outputs are locked for a period (e.g., 150,000 blocks for tier 3). The tree is the sole enforcer of spendability: if an output is in the tree, it can be spent via FCMP++. If it's not in the tree, no valid proof can reference it. By keeping staked outputs out of the tree until their lock expires, we enforce the lock through tree exclusion — the strongest mechanism available in a privacy-preserving system.

Third, **reorg safety.** With a minimum reference block age of 5 blocks, the wallet's proof anchors to a block at least 5 blocks deep. If outputs entered the tree at creation, a shallow reorg could remove outputs that proofs already reference. Deferred insertion adds a buffer.

---

## The Block Header Commitment

Every block header contains a `curve_tree_root` — the tree root after all of that block's outputs have been added. This field participates in the block hash, making the tree state a **consensus commitment**.

Why does this matter? Without it, two nodes could compute subtly different tree roots (due to a bug, different library version, or database corruption) and silently fork — they'd disagree on which transactions are valid. By committing the root in the header, any tree divergence shows up immediately as a block hash mismatch.

When you construct a transaction, you pick a recent block as your `referenceBlock`. The verifier looks up `curve_tree_root` from that block's header and uses it to check your proof. This connects the proof to a specific, consensus-verified tree state.

---

## What the Proof Actually Proves

When you spend an output, the FCMP++ proof says: "I know a path from some leaf in this tree to the root, and I know the opening (the secret randomness) of each Pedersen commitment along that path." The proof never reveals *which* leaf — it's zero-knowledge.

### Layer by layer

For each layer, the proof demonstrates:

1. "I unblinded the Pedersen commitment at this layer" — removing the random blinding factor to reveal the actual hash value
2. "I verified my value is present in the chunk" — the unblinded value matches one of the inputs to this layer's hash
3. "I re-blinded for the next layer" — adding fresh randomness so the next layer's commitment also reveals nothing

This happens once per layer, alternating between Selene and Helios, all the way up to the root. At the root, the blinding factor is set to zero so the final output matches the public tree root committed in the block header.

### Our 4th scalar

Because of our 4th scalar, the proof also demonstrates: "The PQC key hash committed in my leaf matches the one I'm presenting in the transaction" — again, without revealing which leaf. The verifier provides the expected `H(pqc_pk)` as a public input, and the circuit checks that the 4th leaf scalar equals it.

This means an attacker who compromises the classical EC cryptography (e.g., via a quantum computer) still can't steal funds — they'd also need to forge the ML-DSA-65 signature on the PQC key that's bound into the tree leaf. They must break **both** layers.

### The proof system: Generalized Bulletproofs (GBPs)

The actual proof is constructed using a **Generalized Bulletproof** — a modified version of the Bulletproof+ range proofs already used in Monero for amount confidentiality. GBPs can prove arbitrary arithmetic circuit statements, not just range constraints. The FCMP++ circuit is essentially:

"For each layer from leaf to root: unblind, verify membership in chunk, re-blind. Also verify the linking tag (key image) is correctly formed, and that the PQC commitment matches."

The proof size scales as O(log n) where n is the circuit size. For a tree with 100 million outputs, the proof is roughly 2.5-4 KB per input — compact enough to fit in a transaction.

Two GBP proofs are actually generated — one for the Selene layers and one for the Helios layers — because the arithmetic circuits operate over different fields. These are composed into a single FCMP++ proof blob.

---

## Shekyl vs Monero: Summary of Differences

| Aspect | Monero | Shekyl |
|---|---|---|
| **Leaf tuple width** | 3 scalars: `{O.x, I.x, C.x}` | 4 scalars: `{O.x, I.x, C.x, H(pqc_pk)}` |
| **Leaf size** | 96 bytes per output | 128 bytes per output |
| **Circuit internal variables per output** | 6 (three x,y pairs) | 7 (three x,y pairs + one scalar) |
| **Layer 0 scalars per chunk** | 3 × 38 = 114 | 4 × 38 = 152 |
| **Curve cycle** | Helios/Selene (identical) | Helios/Selene (identical) |
| **PQC binding** | None | In-circuit proof that `H(pqc_pk)` matches |
| **Deferred insertion** | Yes (per FCMP++ spec) | Yes, unified across all output types |
| **Tree root in block header** | Yes | Yes |

The tree topology, branching factors, curve cycle, and proof system are all inherited from upstream. The only structural change is one additional scalar per output.

---

## Why This Modified Merkle Tree?

- **Full-chain anonymity**: Prove your output exists *anywhere* in history (not just a small ring of 16 decoys).
- **PQC binding**: The extra `H(pqc_pk)` scalar ties quantum-resistant authorization directly into the proof — an attacker must break both EC and lattice cryptography.
- **Zero-knowledge**: The algebraic structure (Pedersen commitments + curve cycle) lets the proof hide which output while still proving membership and correctness.
- **Efficiency trade-off**: We pay a bit more computation (one extra scalar per output, one more curve multiplication per leaf hash) for dramatically better privacy and future quantum resistance.

This is the core of why our tree is "modified" compared to a classic Merkle tree — it is built from the ground up to support zero-knowledge membership proofs with PQC integration, rather than just simple data integrity.

---

## Terminology Quick Reference

| Term | Meaning |
|---|---|
| **Leaf tuple** | The 4 scalars stored per output: `{O.x, I.x, C.x, H(pqc_pk)}` |
| **Leaf width** | How many scalars per output (Monero: 3, Shekyl: 4) |
| **Chunk** | A group of outputs whose leaf scalars are hashed together in one Pedersen commitment |
| **Branching factor** | How many outputs (layer 0) or children (layer 1+) fit in one chunk |
| **Circuit internals** | The (x,y) coordinate pairs used inside the ZK proof — more values than the leaf tuple, but not stored on-chain |
| **Selene** | First curve in the tower cycle. Leaf scalars are Selene field elements. |
| **Helios** | Second curve. Paired with Selene so their fields interlock. |
| **Tower cycle** | The Selene/Helios pair "towering" over Ed25519, enabling multi-layer Pedersen hashing |
| **Wei25519** | Weierstrass form of Ed25519. Sits at the base of the tower. |
| **Blinding** | Adding randomness to each layer's commitment so the proof reveals nothing about which leaf |
| **GBP** | Generalized Bulletproof — the proof system that proves the entire path from leaf to root |
| **referenceBlock** | The block header whose `curve_tree_root` anchors a transaction's FCMP++ proof |
| **Deferred insertion** | Outputs wait in a pending table until their eligible height before entering the tree |
| **Append-only** | Spent outputs are never removed — the tree only grows |
