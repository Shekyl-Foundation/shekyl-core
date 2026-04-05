### The Big Idea: "Prove your money exists in the entire history… without anyone knowing which one is yours"

In a normal blockchain, proving "I own this coin" is easy — the ledger literally lists who owns what. But that kills privacy. Shekyl (like Monero) wants **full anonymity**: every output should blend into the entire history of the chain so no one can tell which specific coin you are spending.

The solution is a **membership proof**: prove "my output is somewhere in the giant list of all outputs ever created" without revealing *where* it is.

A plain Merkle tree (the classic blockchain structure) lets you prove "this thing is in the list" efficiently, but it doesn't hide *which* thing it is, and it doesn't support the fancy math needed for zero-knowledge (ZK) proofs. So we **modify** the Merkle tree to make it work with zero-knowledge proofs while adding our post-quantum (PQC) binding.

### The Leaf: One Output = Four Numbers (Scalars)

Every time someone receives SHEKYL, the transaction creates an "output" — basically a locked piece of money on the chain. That output contains:

- **O** — the output key (essentially "who can spend this"). This is an Ed25519 elliptic curve point. 

- **I** — the key image generator. This is derived from O (via HashToPoint(O)) so that when you spend it, you produce a unique "key image" that prevents double-spending without revealing which output you used. 

- **C** — the commitment. This is a Pedersen commitment that hides the amount of SHEKYL. It lets the network verify "inputs equal outputs" without showing the actual amounts. 

- **H(pqc\_pk)** — *our addition*. This is a hash of the per-output post-quantum public key. It binds the quantum-resistant authorization key directly to this output inside the tree. 

Elliptic curve points have x and y coordinates, but for this tree we only need the **x-coordinate** (the y can be derived if needed). So each output becomes **four numbers** (scalars in the finite field):

- O.x 

- I.x 

- C.x 

- H(pqc\_pk) 

That's the **Output Tuple** you described — 4 scalars per output (128 bytes total). These four numbers are the "leaf" in our tree.

### The Flat Array: All Outputs Laid End-to-End

The tree doesn't store each leaf in a separate bucket. It lays **all** the leaf scalars out in one giant flat array:

text

```
`Output 0          Output 1          Output 2          Output 3`

`\[O.x, I.x, C.x, H\] \[O.x, I.x, C.x, H\] \[O.x, I.x, C.x, H\] \[O.x, I.x, C.x, H\] ...`
```

This is where people sometimes get confused and say "6 scalars" — if you're looking at two Monero-style outputs side-by-side (each with 3 scalars), you see 6 numbers in a row and might think that's one unit. In Shekyl, each output has 4, so two outputs = 8 scalars in a row.

### Chunking: Grouping for Hashing

The tree doesn't hash every scalar individually. It groups them into **chunks** — think of them as "pages" in a giant book. The chunk size (branching factor) decides how many scalars get combined in one hash operation.

Example: chunk width = 2 outputs (8 scalars per chunk in Shekyl).

text

```
`Chunk 0 (outputs 0-1)              Chunk 1 (outputs 2-3)`

`\[O.x, I.x, C.x, H, O.x, I.x, C.x, H\]  \[O.x, I.x, C.x, H, O.x, I.x, C.x, H\]`

`            ↓                                        ↓`

`      Selene Point₀                            Selene Point₁`
```

Each chunk's scalars are fed into a special "hash" to produce one point on the curve.

### The Special Hash: Pedersen Vector Commitments (Not SHA-256)

This is the key modification. We do **not** use a regular hash like SHA-256. We use a **Pedersen vector commitment** — a cryptographic construction where each scalar is multiplied by a different, publicly known "generator point" on the curve, then all the results are added together.

Think of it like a weighted sum, but with elliptic curve points instead of regular numbers:

text

```
`Hash = scalar₁ × G₁ + scalar₂ × G₂ + scalar₃ × G₃ + scalar₄ × G₄ + ...`
```

Each G is a fixed, publicly known point (a "generator"). The result is a new point on the curve.

Why Pedersen instead of SHA-256? Because Pedersen commitments are **additively homomorphic** — you can do math on the committed values without opening them. This is what makes the zero-knowledge proof work. A normal hash would destroy the algebraic structure we need for ZK proofs.

The cost: Pedersen hashing is much more expensive than SHA-256 (it involves elliptic curve multiplications), and each additional scalar adds one more multiplication. Our 4th scalar (H(pqc\_pk)) is not free — it adds one extra curve multiplication to every leaf-layer hash in the tree.

### The Tower Cycle: Why Two Curves (Selene + Helios)?

A Pedersen commitment takes scalars as input and produces a point as output. But a point lives in a different mathematical space (the curve's base field) than a scalar (the curve's scalar field). You can't directly feed a point back into the next layer as a scalar.

The solution is a **curve cycle** — two curves carefully chosen so that curve A's base field matches curve B's scalar field (and vice versa). FCMP++ uses:

- **Selene** (first curve) 

- **Helios** (second curve) 

These form a "tower" over Ed25519 (the base curve that Monero/Shekyl outputs live on). Wei25519 sits at the bottom; Selene sits on top of it; Helios pairs with Selene.

The tree alternates between them:

text

```
`Leaf scalars (Selene field elements)`

`    ↓ Pedersen hash with Selene generators`

`Layer 0: Selene points`

`    ↓ interpret Selene point x-coords as Helios scalars`

`    ↓ Pedersen hash with Helios generators`

`Layer 1: Helios points`

`    ↓ interpret Helios point x-coords as Selene scalars`

`    ↓ Pedersen hash with Selene generators`

`Layer 2: Selene points`

`    ...continues alternating...`

`Root`
```

This "tower cycle" lets the proof work across multiple levels.

### What the Proof Actually Proves

When you spend an output, the FCMP++ proof says:  
"I know a path from some leaf in this tree to the root, and I know the opening (the secret randomness) of each Pedersen commitment along that path."

The proof never reveals *which* leaf — it's zero-knowledge.

For each layer, the proof demonstrates:  
"I unblinded the Pedersen commitment at this layer, verified my values are present in the chunk, and re-blinded for the next layer."

This happens once per layer, alternating between Selene and Helios, all the way up to the root.

Because of our 4th scalar, the proof also proves:  
"The PQC key hash committed in my leaf matches the one I'm presenting in the transaction" — again without revealing which leaf.

### Why This Modified Merkle Tree?

- **Full-chain anonymity**: Prove your output exists *anywhere* in history (not just a small ring of 16). 

- **PQC binding**: The extra H(pqc\_pk) scalar ties quantum-resistant authorization directly into the proof. 

- **Zero-knowledge**: The algebraic structure (Pedersen commitments + curve cycle) lets the proof hide which output while still proving membership and correctness. 

- **Efficiency trade-off**: We pay a bit more computation (extra scalar per output, more expensive hashing) for dramatically better privacy and future quantum resistance. 

This is the core of why our tree is "modified" compared to a classic Merkle tree — it is built from the ground up to support zero-knowledge membership proofs with PQC integration, rather than just simple data integrity.

## The Output Tuple: What Goes Into a Leaf

Every time someone receives SHEKYL, the transaction creates an "output" on the blockchain. That output has three pieces of cryptographic data that Monero's design requires, plus one that we add:

**O** — the output key. This is essentially "who can spend this money." It's a point on the Ed25519 elliptic curve.

**I** — the key image generator. This is derived deterministically from O via `HashToPoint(O)`. It exists so that when you spend the output, you can produce a "key image" that prevents double-spending without revealing which output you spent.

**C** — the commitment. This is a Pedersen commitment that hides the amount. It lets the network verify that inputs equal outputs (no money created from nothing) without anyone seeing the actual amounts.

**H(pqc\_pk)** — our addition. This is a hash of the per-output post-quantum public key. It binds the quantum-resistant authorization key to the output inside the tree, so the FCMP++ proof simultaneously proves "this output exists" and "this PQC key belongs to it."

Now, elliptic curve points are pairs of coordinates (x, y). But a key insight in the FCMP++ design is that you only need the x-coordinate to uniquely identify a point (up to sign — there are two points with the same x, one "positive" and one "negative"). The spec says: store only the x-coordinates. So each output becomes three field elements (numbers in a specific finite field): `O.x`, `I.x`, `C.x`. We add a fourth: `H(pqc\_pk)`, which is already a scalar (a 32-byte number).

That's one leaf tuple: **4 numbers, each 32 bytes, totaling 128 bytes per output.**

## The Flat Leaf Array: Outputs Laid End to End

The tree doesn't store leaves in separate buckets. It lays all the leaf scalars out in one flat array:

```
`Output 0          Output 1          Output 2`

`\[O.x, I.x, C.x, H\] \[O.x, I.x, C.x, H\] \[O.x, I.x, C.x, H\] ...`
```

This is where the "6-scalar" confusion likely came from — if you're looking at Monero's version (3 scalars per output) and you see two outputs next to each other, you see 6 numbers in a row and might think that's one unit.

## Chunking: Grouping Scalars for Hashing

The tree doesn't hash all the scalars at once. It groups them into **chunks** — think of it like pages in a book. The chunk size (also called the branching factor or "width") determines how many scalars get combined in one hash operation.

Say the chunk width is 2 outputs. In Monero, that's 2 × 3 = 6 scalars per chunk. In Shekyl, that's 2 × 4 = 8 scalars per chunk. The hash combines all the scalars in one chunk into a single output point.

```
`Chunk 0 (outputs 0-1)              Chunk 1 (outputs 2-3)`

`\[O.x, I.x, C.x, H, O.x, I.x, C.x, H\]  \[O.x, I.x, C.x, H, O.x, I.x, C.x, H\]`

`            ↓                                        ↓`

`      Selene Point₀                            Selene Point₁`
```

## The Hash: Pedersen Vector Commitments

Here's where it gets interesting. The "hash" used is not SHA-256 or any conventional hash. It's a **Pedersen vector commitment** — a cryptographic construction where you multiply each scalar by a different, publicly known "generator point" on the curve, then add the results together.

Think of it like a weighted sum, but with elliptic curve points instead of regular numbers:

```
`Hash = scalar₁ × G₁ + scalar₂ × G₂ + scalar₃ × G₃ + scalar₄ × G₄ + ...`
```

Each `G` is a fixed, publicly known point (a "generator"). Each scalar is one of our leaf values. The result is a new point on the curve.

Why Pedersen and not SHA-256? Because Pedersen commitments are **additively homomorphic** — you can do math on the committed values without opening them. This is what makes the zero-knowledge proof work. The prover can show "I know which leaf is mine" without revealing which one, because the proof operates on the algebraic structure of the commitments rather than on raw data. A conventional hash would destroy that algebraic structure.

The cost of this: Pedersen hashing is much more expensive than SHA-256 (it's elliptic curve multiplication), and each additional scalar in the leaf means one more curve multiplication per hash. That's why our 4th scalar isn't free — it adds one more `scalar × Generator` operation to every leaf-layer hash in the tree.

## The Tower Cycle: Why Two Curves?

Here's the subtlest part. A Pedersen commitment takes scalars as input and produces a **point** as output. But a point lives in a different mathematical space than a scalar. Specifically, a point's coordinates are elements of the curve's "base field," while scalars are elements of the curve's "scalar field." These are different-sized number systems.

To build a multi-layer tree, the output of one layer's hash needs to become the input to the next layer's hash. But the output is a point (base field), and the input needs to be a scalar (scalar field). You can't directly feed one into the other.

The solution is a **curve cycle** — two curves where curve A's base field equals curve B's scalar field, and vice versa. The FCMP++ design uses:

- **Selene** — the first curve 

- **Helios** — the second curve 

These are specifically constructed so that a Selene point's coordinates are valid Helios scalars, and a Helios point's coordinates are valid Selene scalars.

The tree alternates between them:

```
`Leaf scalars (Selene field elements)`

`    ↓ hash with Selene generators`

`Layer 0: Selene points`

`    ↓ interpret Selene point x-coords as Helios scalars`

`    ↓ hash with Helios generators`

`Layer 1: Helios points`

`    ↓ interpret Helios point x-coords as Selene scalars`

`    ↓ hash with Selene generators`

`Layer 2: Selene points`

`    ↓ ...continues alternating...`

`Root`
```

This is the "tower cycle" — it towers over Ed25519 (the base curve that Monero/Shekyl outputs live on). Wei25519 (a different representation of the same curve as Ed25519) sits at the bottom, Selene sits on top of it (its scalar field matches Ed25519's base field), and Helios pairs with Selene to form the cycle.

## What the Proof Actually Proves

When you spend an output, the FCMP++ proof says: "I know a path from some leaf in this tree to the root, and I know the opening (the secret randomness) of each Pedersen commitment along that path." The proof never reveals *which* leaf — it's zero-knowledge.

For each layer, the proof demonstrates: "I unblineded the Pedersen commitment at this layer, verified my value is present in the chunk, and re-blinded for the next layer." This happens once per layer, alternating between Selene and Helios, all the way up to the root.

Our 4th scalar means the proof also demonstrates: "The PQC key hash committed in my leaf matches the one I'm presenting in the transaction" — again, without revealing which leaf.

## The Practical Summary

For explaining to others:

**Monero** stores 3 numbers per output in the tree (who owns it, anti-double-spend data, and the hidden amount). Each hash combines a few outputs' worth of numbers using special algebraic hashing that preserves the math needed for zero-knowledge proofs. The tree alternates between two paired curves because the math requires it.

**Shekyl** stores 4 numbers per output — the same three plus a commitment to the quantum-resistant key. This means each hash operation does slightly more work (one extra curve multiplication), and the zero-knowledge circuit has one more thing to prove per leaf. That's the scope of our divergence from upstream — one additional number per output, carried through the entire tree.

The chunk width (how many outputs get grouped per hash) is a separate parameter from the leaf width (how many numbers per output). Someone seeing "6 scalars" was almost certainly looking at two Monero outputs' worth of data (2 × 3 = 6) in a single chunk and thinking that was one leaf.

