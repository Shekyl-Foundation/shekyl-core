# One hashing actor owns the RandomX caches

**Status:** OPEN — Round 0 (2026-11-10). The direction is ruled (Rick, 2026-11-10): replace the cache slots and their bookkeeping with an actor. Everything marked **PROPOSED** below is this round's answer to the design review's brief and is not ruled. No code is built on this document until HA-Q1…HA-Q8 (§9) are ruled.

**Ground:** `dev` at `cf561f79d6`, which includes #1338. Every `path:line` below was read at that revision.

**Identifiers:** `HA-F*` are this round's findings, `HA-Q*` its questions, `HA-R*` the rulings when they come.

## 1. The problem is a class

A RandomX cache is 256 MiB. Today a cache stays resident until someone remembers to release it, and four times nobody did:

1. **A2 (alpha.11).** The previous epoch's cache stayed resident after the window stopped naming it.
2. **#1301.** Its release never ran on a live node, because a published record of the slots had drifted from the slots. #1338 fixed that.
3. **The fork seed (on `dev`).** A branch form prepares a fork's own seed into the second slot (`span.rs:993`, `:1149`). No window names that seed, so nothing releases it before the next epoch's pin.
4. **Chain sync's branch cache (on `dev`, HA-F1).** The header executor keeps one cache of its own outside the store, and nothing drops it (§3).

Each fix so far made the bookkeeping more careful. This design removes the bookkeeping: one owner holds every cache, and what it holds is computed from what the node needs.

## 2. Who touches a cache today

Read at `cf561f79d6`. "Builds" means it can cause a 256 MiB derivation. "Holds" means it keeps an `Arc<PreparedCache>` past one call.

| Consumer | Where | Builds | Holds |
| --- | --- | --- | --- |
| The cache store's two slots | `shekyl-pow-randomx/src/cache_store.rs:134`, `:443–:651` | `lookup_or_derive`, `pin_canonical` | the canonical and transient slots |
| Ingest: the window install | `shekyl-chain-ingest/src/window.rs:40–:103` | pins the window's pair | nothing; it records the window under `pin_lock` |
| Ingest: a run's pins | `span.rs:249` (`pin_seeds`) | pins the run's seeds | nothing |
| Ingest: a branch form and a switch | `span.rs:977–:1011`, `:1134–:1158` | `prepare_seed` into the transient slot | the cache for the form's life, so an evicted cache can outlive its slot |
| Ingest: the replay pipeline | `pipeline.rs:975` | `pin_seed` on a store of its own | nothing |
| Chain sync: header proofs on a main seed | `shekyl-chain-sync-runtime/src/executor.rs:103` (`CachePlan::Main`) | no | no; a miss is `Proved::NotHeld` |
| Chain sync: header proofs on a branch seed | `executor.rs:54`, `:104–:112`, `:196–:207` (`CachePlan::Branch`) | derives outside the store | **one cache, until another branch seed replaces it** |
| Chain sync: the past-cap evidence check | `executor.rs:113–:118`, `:209` (`CachePlan::Evidence`) | derives outside the store | for the job |
| The miner | `shekyl-miner/src/miner.rs:308` | no | for the posted job's life |
| `calc_pow` | `shekyl-daemon-rpc/src/read_facts.rs:127` (`AdmittedPow`), `store_facts.rs:161` | no | from the lookup to the hash, across its permit wait |
| The node | `shekyl-node/src/lib.rs:283`, `mining.rs:207` | builds the store and hands it out | — |
| Tools and tests | `bin/shekyl-chain-replay.rs:326`, `shekyl-p2p-harness/src/sync/node.rs:164`, `scenario.rs:371`, `:497`, `:539`, `:570`, `shekyl-chain-sync/src/proof.rs:42` | `pin_seed` on stores of their own | nothing |

Two readers consume the published slots, not a cache: the tip follower before a template build (`follower.rs:700`, `seed_now`) and the sync owner waiting on a seed it found absent (`shekyl-chain-sync-runtime/src/owner.rs:541`, `:1321`).

## 3. Findings

- **HA-F1. Chain sync holds caches the brief's delete list does not name.** The executor derives a branch seed's cache outside the store and keeps it in `Executor::branch` (`executor.rs:54`). The only write to that field is a replacement by another branch seed (`:196–:207`). The ruling it implements says the cache is "dropped when that seed epoch's headers are done" (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2 step 3). The code does not drop it. Initial sync is the branch case, so a node that synced across a seed boundary keeps that cache for the life of the process. Read from the code; not observed on a live node.
- **HA-F2. The same seed can be built twice.** A fork's headers are proven under the executor's branch cache, then its bodies arrive as alternatives and the ingest prepares the same seed into the transient slot. The two paths share no cache.
- **HA-F3. Today's ceiling is five caches, not three.** The canonical slot, the transient slot, one evicted cache a branch form still holds (`service.rs:563–:568`), the executor's branch cache, and one evidence cache while a check runs. That is 1,280 MiB. The miner and `calc_pow` can each also keep an evicted cache alive until their hash returns.
- **HA-F4. `needed_seeds` cannot be a function of the store alone.** A header run's earned seed (65 headers proven on the run's own branch) lives in the sync model's run state. The fork's blocks are not stored rows until their bodies arrive. The evidence check's seed is likewise the sync model's. So the facts come from two places: the ingest (the store) and chain sync (its runs).
- **HA-F5. Honest operation wants three seeds through the whole of initial sync, not only near a switch.** The ingest connects bodies under its window (one seed, two for 784 blocks after each switch) while header sync runs ahead under the frontier's seed.
- **HA-F6. The evidence check has a ruled cache of its own** (Rick, 2026-10-19; `DRS_X_STORE_FLIP.md` DX-Q2 item 6). With the brief's "two main seeds plus one fork seat" it is a fourth.
- **HA-F7. Three caches leave PB-R1 about 100 MiB; four exceed it.** PB-R1 is 2 GiB with mining off (`DAEMON_REDB_STORE.md` §1.3a): a 1 GiB store cache, a 64 MiB pool cache, "about 256 MiB" of RandomX and the process. The process outside the caches read about 90 MiB on regtest (RssAnon 354,624 kB with one cache, 2026-11-09). Three caches make 1,024 + 64 + 768 + 90 = 1,946 MiB. Four make 2,202 MiB. This is arithmetic from the budget row and one regtest reading, not a floor-device run at design load.
- **HA-F8. A switch prepares caches it rarely hashes under.** `prepare_all` (`span.rs:1134`) derives each branch seed a promoted run names, but the switch forms through `Recalled` (`substrate.rs:230`), which answers from the proof-of-work hash recorded when each block first arrived. Under the actor a switch asks for a cache only for a block with no recorded hash.
- **HA-F9. A run's seeds are already in the window.** A run is at most the arrival window, 32 blocks by default (`pipeline.rs:105`), and a seed is first named 65 blocks above its block, so the block is committed before any block of the run names it. The window reaches `max(cap, 65)` above the connecting height (`cache_window.rs:51`) and names it. This holds while the arrival window is at most the seed lag (64); `ServiceConfig::room` is not held to that today, and the largest one configured is 64 (`shekyl-p2p-harness/src/sync/chain.rs:247`). **Not reconciled:** `window.rs:87–:90` says a run pins seeds the window "cannot name". By this arithmetic the window names the same two seeds with the canonical role on the other one; this round did not find a run seed outside the pair.
- **HA-F10. The earlier "no cache store" proposal was rejected for unbounded holding** (`cache_store.rs:17–:34`; `docs/completed/RANDOMX_V2_PHASE2F_PLAN.md` §3.1 Round 2, alternatives (d) and (g)): consumers managing `Arc<PreparedCache>` themselves gave no cap. That objection does not reach this design, because the cap is the actor's and no consumer holds an `Arc`. It is the bar the lending type in §4.3 has to meet.

## 4. The design — PROPOSED

One actor owns every `PreparedCache` in the process. Nothing else builds, holds or frees one.

### 4.1 Needs

The actor's input is a fact: the seeds the node needs. Each source sends its whole list whenever it changes, and a new list replaces that source's previous one.

- **The chain's needs** come from the ingest, computed by `needed_seeds` in `cache_window.rs` beside `seeds_for` and `seeds_on`. It is a pure function of a store snapshot and the rules:
  - the window's pair, canonical first, as `seeds_on` returns it today;
  - for each held branch tip inside the cap (`ChainStore::alt_blocks`), the seed its children would hash under, when that seed is the branch's own block, with the tip's cumulative work.
- **Chain sync's needs** come from the sync owner: the earned branch seed of each run it is proving, with the run's proven work, and the evidence check's seed while a check runs (HA-F4).

The actor knows nothing about chains. It sees seeds, each with a rank and the hasher class its build is paid under.

### 4.2 What is resident

Residency is a pure function of the two lists and the jobs in flight:

1. **The main pair** (at most two). Always resident once built. Nothing evicts it.
2. **One off-main seat.** It holds the seed of the off-main job in flight, when there is one. Otherwise it holds the off-main claim with the most work. Off-main jobs for different seeds run one at a time, which replaces the branch gate (`service.rs:568`).
3. **Nothing else.** A cache that is in neither place and has no job in flight is freed.

So the bound is three caches, 768 MiB. A cache that has left both lists while a job still hashes under it is *draining*: it is freed when that job returns or is cancelled, and it is counted and exported separately (§7). A drain lasts one hash for a form and one hash at nice 19 for the miner.

Whether the evidence check takes the seat or has a fourth, job-scoped cache as ruled on 2026-10-19 is HA-Q2.

### 4.3 Jobs borrow

Work reaches a cache only through a job. The crate's public surface has no `PreparedCache` and no `Arc` in any signature:

```rust
/// The caches one job may hash under. Borrowed for the job; not `Clone`.
pub struct Lent<'job> { /* private */ }

impl Lent<'_> {
    /// RandomX over `blob` under `seed`. `None` if the job did not name `seed`.
    pub fn hash(&self, seed: &Seedhash, blob: &[u8]) -> Option<[u8; 32]>;
}

impl Hasher {
    /// Run `job` under the named seeds and one permit of `class`.
    pub fn run<R>(
        &self,
        class: Class,
        seeds: &[Seedhash],
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&Lent<'job>) -> R,
    ) -> Result<R, Refused>;
}
```

- `Lent` hands out hashes, never the cache, so there is nothing to clone.
- The `for<'job>` bound means `R` cannot name the job's lifetime, so a `Lent` cannot be returned or stored.
- `run` blocks its caller: it waits for the seeds to be resident (a build in progress is waited for), then for the permit, then calls `job` on the caller's thread. Callers already wait for permits on blocking threads (`span.rs:418`), so the node's thread count (`shekyl-node/src/lib.rs`, "Blocking threads") stands.
- **How a form gets its hash (the brief's Q2).** The ingest's substrate becomes a struct over a `&Lent` and the clock. `Substrate::longhash` stays synchronous and calls `lent.hash`. `form_on_branch` (`span.rs:977`), `spawn_form` (`:294`) and `form_switch` (`:1163`) each become one `run` whose closure builds that substrate and calls `form` or `form_plan`. `Branch` (`substrate.rs:308`) and the executor's `HeldSubstrate` (`executor.rs:313`) go: both exist to carry a held `Arc`. `Recalled` stays.
- **The miner** uses a second entry point, `mine`, that lends for the posted job's life and takes one `Class::Miner` permit per hash inside `Lent::hash`, as `miner.rs:327` does now. Its closure receives a cancel flag the actor sets when the job's seed leaves the lists.

### 4.4 Refusals

```rust
pub enum Refused {
    /// No list names the seed. The caller did not send the need first.
    NotNeeded { seed: Seedhash },
    /// A list names it, and the off-main seat is held by a claim with more work.
    NotSeated { seed: Seedhash },
    /// The caller's stop flag was set before the job began.
    Stopped,
}
```

The refusal is typed and quiet in the actor. What it means is the caller's: the ingest faults on `NotNeeded` (its own defect, as `SeedNotInWindow` is today), `calc_pow` answers `PowDecline::SeedNotHeld` (an RPC caller names the seed, so this is ordinary), the miner leaves the job, and chain sync drops the run (`Proved::NotHeld`).

### 4.5 Builds and the order

The actor's loop only takes lists, grants and releases leases, and queues builds. It never hashes and never derives. One builder thread derives one cache at a time, taking one permit of the class the need carries.

- **Order:** the canonical seed, then the other main seed, then the seat.
- **The canonical seed is known 64 blocks before it is used**, because the window names a seed once its block is on the chain. It is built then, so a canonical job waits for a build only at a cold start or after a reorg that replaces the seed block.
- **A running build is not interrupted.** The worst wait for a canonical job is therefore one build in progress plus its own: two derivations, about 4.2 s on the floor device (§5 Q1).
- **A build never evicts a main cache**, and the seat's build starts only after the cache it replaces has no job in flight.

### 4.6 Publication

The actor publishes its resident seeds on a watch. That replaces `Door::seeds`, `published_seeds`, `seed_now` and `seed_pair`: the follower builds a template when the canonical seed is resident, a span waits for it before its first hash, and the sync owner waits on it for a seed it found unseated.

### 4.7 Stop

Each caller passes its own stop flag, as it passes one to `Budget::acquire_unless` today, so the node's stop order (`shekyl-node/src/lib.rs`, "Stop") is unchanged through step 6. A set flag refuses that caller's next job and wakes its waits; a hash in progress finishes. The actor is built before every consumer and stopped after the miner drains (step 7): by then no lease is out, and it frees its caches and joins its builder.

## 5. Answers to the brief's questions

### Q1. The bound, and what a rebuild costs

- **A fourth main seed: no.** The window is `cap + max(cap, 65)` wide, 1,440 blocks at the production cap, inside one 2,048-block epoch; a compile-time assertion holds `D_MAX` to that (`cache_window.rs:41`). A run adds none (HA-F9).
- **A fork across two seed boundaries: the code does not exclude it.** A held fork's root is within the cap below the tip (the death rule, `alt.rs:265`), but nothing bounds how far above the tip it reaches. It would need about 1,400 blocks more than the main chain while carrying less work, which the difficulty rule makes implausible; no line of code forbids it. The design does not depend on it: a need names one seed per branch tip, and a job names its own.
- **Three is the honest count, and it is routine** during initial sync (HA-F5).
- **A fourth is the evidence check** as ruled (HA-F6, HA-Q2).
- **`PreparedCache::derive` on the floor device:** about 2.1 s, below.

**Measured 2026-11-10 on the floor device** (Pi 4, `dev` at `cf561f79d6`, the Release `cache_derive` bench, 100 samples a run, the device's resident testnet daemon running throughout at about 188 % CPU):

| run | low | median | high |
| --- | --- | --- | --- |
| 1 | 2.0900 s | 2.0946 s | 2.0994 s |
| 2 | 2.1118 s | 2.1149 s | 2.1181 s |
| 3 | 2.0926 s | 2.0971 s | 2.1021 s |

- One forced rebuild costs about **2.1 s** of one core on the floor device, 6.1 times the 341 ms x86 figure (`rust/shekyl-pow-randomx/BENCH_RESULTS.md`).
- The readings were taken beside a busy node, which is the condition a forced rebuild meets. They are not an idle-device figure.
- The worst wait in §4.5, two derivations, is about 4.2 s.
- The record is in shekyl-dev `infrastructure/captures/randomx-cache-actor/2026-11-10/`. The bench is not yet a row of the bench suite; it joins it with the crate (Q5 step 2).

### Q2. How a form gets its hash

§4.3. Confirmed against `form_on_branch` and the run path: both already run `form` inside one blocking closure that holds the permit, and the closure is where the lending scope goes.

### Q3. Who owns scheduling

The permits move behind the actor's entry points. `Budget` keeps its type and its class rules; consumers stop holding one.

What breaks if they stay with the callers:

- **A deadlock on a small budget.** A caller that holds a permit and then waits for a cache waits on a build, and the build needs a permit. On a one-permit budget that never ends. Today the order "gate, permit, `pin_lock`" is a comment each call site must obey (`service.rs:555–:568`). One entry point that takes the lease, then the permit, makes it the only order there is.
- **An unpriced build.** A build started by a list has no caller thread to hold its permit, so the actor needs the budget anyway.
- **The branch gate has no owner.** It exists to bound live caches to three. The bound is the seat now.

### Q4. Where the actor lives

A new crate above `shekyl-pow-randomx` and `shekyl-hash-budget`, proposed name `shekyl-hasher`. Not in `shekyl-pow-randomx`: that crate is held to isolation invariants "a scheduler has no business under" (`shekyl-hash-budget/Cargo.toml`). `PreparedCache::derive` therefore stays `pub`, and a gate holds its callers to the actor, the benches and the differential harness. The mailbox mechanism is a Round 1 detail with one constraint: the entry points are called from blocking threads and from the miner's own threads, which hold no runtime handle.

### Q5. The PR sequence

1. **This document.**
2. **`shekyl-hasher`, with no consumer** (rule 26: a new crate is its own PR). The actor, the lists, the seat, leases, builds, the metric, and its own tests. Built and tested; nothing calls it. The floor derive bench joins the bench suite here.
3. **The cutover, one PR, driven by the deletion.** The cache store's slots are shared by every consumer in §2, so any split leaves two owners of caches in one process. This PR deletes the slot API and moves the ingest, chain sync's executor, the miner, `calc_pow`, the node, the replay binary, the pipeline and the test harnesses onto the actor, with `needed_seeds` and the invariant test.
4. **Close-out.** The live RSS capture repeated with a fork case, PB-R1's cache rows restated against the ruled bound, and this document moved or made a contract (rule 95).

## 6. What it deletes

The brief's list stands. HA-F1 adds:

- **In `shekyl-chain-sync-runtime`:** `Executor::branch`, `branch_held`, `branch_cache`, `derive`, `Prepared` and `HeldSubstrate` (`executor.rs:54`, `:101–:120`, `:184–:217`, `:302–:338`), and the executor's own `Budget`.
- **In `shekyl-chain-ingest`:** `Branch` (`substrate.rs:308–:365`) and `ProductionSubstrate`'s `Arc<CacheStore>`.
- **In `shekyl-daemon-rpc`:** `AdmittedPow`'s `Arc<PreparedCache>` (`read_facts.rs:127`).
- **In `shekyl-node`:** `mining.rs:207`'s `Arc<CacheStore>`.
- **Tools and tests** in §2's last row take the actor: with the slot API gone there is no second pathway to leave them on.

## 7. Tests

The brief's §4 stands, with these changes:

- **The invariant has two halves.** *Always:* the actor holds no cache outside what a fresh actor would hold for the same lists, except a draining one with a job in flight. That half is the class in §1 and is checked after every reply. *Once quiet:* it holds exactly that set. A build in progress makes the second half false for a moment, so it is checked when no build and no job is running.
- **Added red tests, each failing on `dev`:**
  - a header run across a seed boundary that then ends: its cache is freed (HA-F1);
  - a fork whose headers were proven and whose bodies then arrive: one build, not two (HA-F2);
  - a switch whose promoted blocks all have recorded hashes: no build (HA-F8).
- **The metric** exports resident and draining counts separately.
- **A gate** holds `PreparedCache::derive` and `Arc<PreparedCache>` to the paths in Q4, and asserts those paths exist (rule 47).

## 8. Wargame

- **Forced rebuilds through the seat.** The seat goes to the most work, and an off-main job borrows it. An attacker with one held fork past its seed point (66 blocks of real work: the seed block and the 65 above it) sends a free invalid block on it while a heavier claim holds the seat. That costs this node the fork's build, and the heavier claim's rebuild when it next needs the seat. Whether the displaced claim is rebuilt at once or at its next job is HA-Q4.
- **Evicting the main chain's previous seed.** It cannot be done: the main pair is not in the seat's order. A pop across the switch finds the previous seed resident for the whole of the window that names it.
- **Initial sync against a cheap fork.** Early blocks are cheap, so a forged run of 65 early headers earns a seed cheaply. It ranks by proven work, below the honest frontier, and is refused `NotSeated` while the frontier holds the seat.
- **A lent cache held too long.** §4.3's types. An `Arc<PreparedCache>` outside the crate fails the gate in §7.
- **The actor stalling.** §4.5.
- **Shutdown.** §4.7.

## 9. Questions for ruling

- **HA-Q1.** The bound: the main pair plus one off-main seat, three caches.
- **HA-Q2.** The evidence check: take the seat (displacing a fork's or a run's cache for the check, three in all), or keep its own job-scoped cache as ruled on 2026-10-19 (four while a check runs, which HA-F7 puts past PB-R1 by arithmetic).
- **HA-Q3.** Chain sync is a second source of needs (HA-F4), so the brief's "`needed_seeds` stays in the ingest" covers the chain's list only.
- **HA-Q4.** After an off-main job borrows the seat from a heavier claim: rebuild the heavier claim's cache at once (the "once quiet" invariant holds; two builds per forced job) or at its next job (one build; the invariant's second half is weakened to "a subset").
- **HA-Q5.** The permits move behind the actor's entry points (Q3).
- **HA-Q6.** The crate: `shekyl-hasher`, above `shekyl-pow-randomx` and `shekyl-hash-budget` (Q4).
- **HA-Q7.** The cut: four PRs, the cutover atomic (Q5).
- **HA-Q8.** A run's seeds: either `needed_seeds` takes the seeds of the run in flight, as the brief has it, or `ServiceConfig::room` is held to at most the seed lag by a refusal at construction and HA-F9 is proven first, so the chain's list is a function of the store alone.

## 10. What this round read, and what it did not

Read at `cf561f79d6`: `cache_store.rs` (the store and its header), both `substrate.rs` files, `cache_window.rs`, `window.rs`, `span.rs`'s run, alternative and switch paths, `service.rs`'s shared state and stop, `executor.rs` whole, `peer.rs:631–:664`, the miner's work loop, `calc_pow`'s admission, the node's composition and stop order, `shekyl-hash-budget`'s header, and CS-Q2 step 3 and DX-Q2 items 1 and 6.

Not read: `switch.rs` and `plan_form.rs` beyond their call sites, the sync owner past its seed wait, the scenario harness beyond its pin sites, and `shekyl-randomx-differential`. No fleet node was read for HA-F1; the finding is from the code.
