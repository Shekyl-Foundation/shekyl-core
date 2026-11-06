# Archival storage landscape — dispositions with reopen clauses

**Status:** OPEN — dispositions **PROPOSED 2026-10-10**. Decision
authority: Rick. Companion to
[`../V3_SHARD_VISUALIZATION.md`](../V3_SHARD_VISUALIZATION.md) (*SV-D
continuation*) and [`SHARD_VIEW_FETCH.md`](SHARD_VIEW_FETCH.md).
Identifier family `ASL-1`…`ASL-N`, registered at birth (rule 94 §1).

**One sentence.** A 2024–2026 survey of hash, streaming, erasure-coded
storage, post-quantum data-availability, proof-of-replication, and
visual-hash results, each mapped to a Shekyl ruling already in force,
with a named reopen clause (rules 21 / 23). Nothing here is adopted
into genesis code except `ASL-9` (the evidence base for the
recognizer-not-verifier wording).

**Rule 17.** Every row is a *lead*. A later change that adopts a crate,
a primitive, or a feature attributed here re-verifies that claim at
source (workspace pin, API, property, feature flag) before the
recommendation is written into an implementing PR.

Dispositions are **PROPOSED** until this document is ruled. A row's
status is in the row (rule 23 / 95). `REJECTED` / `NOT NOW` /
`VALIDATES` / `ADOPTED AS EVIDENCE` / `CONTINGENCY` / `NONE` are the
tokens.

---

## `ASL-1` — KangarooTwelve / TurboSHAKE (RFC 9861, Oct 2025) — NOT NOW

Parallel tree hashing over Keccak-p[12]. KT256 is reported at ~4–6
GiB/s. The view hash (`SV-D1`) is a cSHAKE256 fold computed per
transaction while streaming, bounded by Tor throughput, not by hashing.

**Disposition: not now.** The fold is not the binding cost.

**Reopen if** `W` grows past ~100 MB **or** `BA-T6` (client verify per
shard size on the floor device) shows the fold binding on the Pi 4.
Falsify by a committed floor capture under `docs/benchmarks/` whose
verify-time attribution names the cSHAKE fold as the majority term.

**Re-evaluation:** a design-round 1 amendment of `SV-D1`'s primitive,
with a `-v2` customization string and a `candidate.v2` only if the
picture's seed width or domain changes.

## `ASL-2` — BLAKE3 / Bao verified streaming — VALIDATES

Range verification against one root. Shekyl verifies per transaction
against skeleton rows every node already holds (`txs_prunable_hash`,
`txs_pqc_auth_hash`), which is strictly stronger for this purpose: no
outboard tree, no root to trust, one transaction resident (`PDM-Q6`
item 5, `SV-D8`).

**Disposition: validates the design; nothing to adopt.**

**Reopen if** a consumer appears that must verify a *byte range that is
not a transaction* against a single root this node does not already
have rows for. Falsify by a production caller that cannot name a
skeleton row for the range it wants.

## `ASL-3` — Erasure coding and self-healing (Walrus Red Stuff; 2D RS) — NOT NOW (post-genesis)

2D Reed–Solomon / Red Stuff: ~4.5× expansion, O(blob/n) recovery. A
holder of a sliver is not a holder of a shard. `TJ-A/R1` rules the
challenge must demand the shard.

**Disposition: not for genesis.** Changing the good from "the shard" to
"a sliver" reopens the challenge, the market hint, and `WSS-Q7`.

**Reopen if** testnet coverage data shows persistent shards below `L`
holders (the scarcity the market hint exists to correct) after the
hint has been live for a named window. Falsify by
`get_archival_shard_coverage` reporting a shard with `bonded_count < L`
across that window. Target: **post-genesis** (named blocker: no
coverage data until there is a live testnet with bonded holders).

**Re-evaluation:** a new round, not an amendment of `TJ-A/R1` in place.
The challenge's demand stays the shard unless that round rules
otherwise.

## `ASL-4` — Post-quantum data-availability sampling (FRIDA, ZODA) — NONE (no consumer)

FRIDA (CRYPTO 2024), ZODA (2025), and a Lean-verified PQ-DAS
construction: hash-based, no trusted setup, polylog overhead. The only
DAS family Shekyl could adopt — KZG is not PQ.

**Disposition: no consumer today.** Light-client sampling of archival
bodies is not a genesis surface.

**Reopen if** a ratified light-client (or a pruned-daemon sampling
path) is specified that must sample archival *bodies* it does not
hold, and the sampler cannot be the existing per-tx skeleton rows.
Falsify by a living-contract section that names that sampler.

## `ASL-5` — Proof of replication / replica packing — CONTINGENCY (unchanged)

Arweave replica.2.9: per-partition entropy from RandomX, XOR
enciphering; Filecoin PoRep. Already named as the non-genesis
contingency if the free-rider margin fails
(`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md` reopen (d)). Design note
worth keeping: entropy generation and enciphering split; Shekyl has
RandomX in-tree.

**Disposition: contingency, unchanged.**

**Reopen if** reopen (d) of that document fires. This row does not add
a second criterion.

## `ASL-6` — Ethereum history expiry (EIP-4444) and Portal — CITE

Confirms the 1-of-N distributed-history model Shekyl already runs.
Portal spreads content by id with a cycle structure rather than by
market. Shekyl's answer is the market hint (`SL-D4`).

**Disposition: cite** in `V3_STAKER_ARCHIVAL.md` as a comparable. The
practical take-away is the coverage-health view
(`V3_SHARD_VISUALIZATION.md` *Coverage-health view*) — holders per
shard, scarcity, close heights — over `get_archival_shard_coverage`.

**Reopen if** a Portal-style cycle assignment is proposed as a
*replacement* for `SL-D4`. That is a `SL-D` question, not an adoption
of Portal.

## `ASL-7` — Lattice accumulators and vector commitments — NONE

COMPASS 2025 (~4.3 KiB constant witnesses) and Wee–Wu lattice VCs.
Merkle and hash-based commitments are already PQ; the per-tx rows are
the commitment.

**Disposition: none.**

**Reopen if** a consumer needs a constant-size witness for a set this
node does not already commit per element. Falsify by a ruled question
that names that set.

## `ASL-8` — Hash-based signatures for receipts — NONE

SLH-DSA ~7.8 KB vs ML-DSA-44 ~2.4 KB; STARK aggregation at seconds per
signature. The receipt key is ruled FN-DSA-1024 (Slice C / `SCS-`;
`ARCHIVAL_SERVE_CREDIT_SPEC.md`).

**Disposition: none.**

**Reopen if** the FN-DSA-1024 ruling is reopened on its own criterion
(FIPS 206 final and a production caller that cannot carry FN-DSA). This
row does not add a second criterion.

## `ASL-9` — Visual-hash security literature — ADOPTED AS EVIDENCE

CEAL, CLPS, ACSAC 2009, perceptual-hash near-collision attacks (Prokos
et al. 2023; LeBlanc-Albarel 2024/26). Directly informs the entropy
audit, the CVD gate, and the recognizer-not-verifier wording in
`V3_SHARD_VISUALIZATION.md` *SV-D continuation*.

**Disposition: adopted as the evidence base.** No primitive is imported.

**Reopen if** a later user-study or a `candidate.v2` compositor changes
the perceptible-bit method; the citations stay, the numbers move by
amendment.

## `ASL-10` — Aperiodic monotile (hat / Spectre, 2023/24) — candidate.v2 OPTION

Smith–Myers–Kaplan–Goodman-Strauss chiral aperiodic monotile.
Deterministic substitution. Rust implementations exist.

**Disposition: `candidate.v2` option only**, and only riding a
functional change (`V3_SHARD_VISUALIZATION.md` *candidate.v2 criteria*
item 3). Aesthetic work does not mint a spec version.

**Reopen if** trigger (1) or (2) of those criteria fires and the
replacement compositor is being designed. Spectre is then an algorithm
candidate, not a requirement.

---

## What this document is not

- Not a shopping list. `NOT NOW` and `NONE` leave **zero code symbols**
  (rule 23).
- Not a FOLLOWUPS queue. A row that is `NOT NOW` with a named external
  blocker (`ASL-3`) is the deferral record; it does not also need a
  FOLLOWUPS line unless an increment is scheduled.
- Not a citation of host measurements. Floor numbers live in
  `docs/benchmarks/` under the roles those captures already use.

## References

- RFC 9861, *KangarooTwelve and TurboSHAKE*, October 2025
- Bao / BLAKE3 verified streaming (Bao crate; BLAKE3 spec)
- Walrus *Red Stuff* (Mysten / Sui storage)
- FRIDA (CRYPTO 2024); ZODA (2025); Lean-verified PQ-DAS
- Arweave replica.2.9; Filecoin PoRep
- EIP-4444 (history expiry, July 2025); Portal history network
- COMPASS 2025 lattice accumulators; Wee–Wu lattice VCs
- FIPS 205 (SLH-DSA); FIPS 204 (ML-DSA); FN-DSA (FIPS 206 draft)
- Hsiao / Stubblefield / Wallach, ACSAC 2009 visual hashes
- CLPS / T-Flag usability studies; CEAL learned visual hashes
- Prokos et al. 2023; LeBlanc-Albarel 2024/26 perceptual-hash
  near-collisions
- Smith, Myers, Kaplan, Goodman-Strauss, aperiodic monotile 2023/24
