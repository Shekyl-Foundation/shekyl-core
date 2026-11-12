# One hashing actor owns the RandomX caches

**Status:** OPEN — Round 0 RULED 2026-11-10 and 2026-11-11 (Rick): HA-R1…HA-R8, §4. §6 step 2 BUILT (as of 2026-11-12): the crate `rust/shekyl-hasher`, which §5 describes; nothing calls it yet. Step 3, the cutover, is next.

**Ground:** `dev` at `ce8b1630e0`. §2, §3 and every `path:line` outside `rust/shekyl-hasher` were read at `cf561f79d6`, which includes #1338, and re-read at `ce8b1630e0`.

**Identifiers:** `HA-F*` are this round's findings, `HA-R*` its rulings.

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
- **HA-F3. Today nothing bounds the count, and five is reached by the code's own design.** The canonical slot, the transient slot, one evicted cache a branch form still holds (`service.rs:563–:568`), the executor's branch cache, and one evidence cache while a check runs: 1,280 MiB. That is a configuration, not a ceiling. A switch keeps a cache for every branch seed its promoted run names (`prepare_all`, `span.rs:1134–:1158`), the miner keeps one for its posted job's life (`miner.rs:308`), and `calc_pow` keeps one across its permit wait and its hash (`read_facts.rs:127`). Each of those can hold an evicted cache alive beside the five.
- **HA-F4. `needed_seeds` cannot be a function of the store alone.** A header run's earned seed (65 headers proven on the run's own branch) lives in the sync model's run state. The fork's blocks are not stored rows until their bodies arrive. The evidence check's seed is likewise the sync model's. So the facts come from two places: the ingest (the store) and chain sync (its runs). HA-R4 makes them inputs of one ranking function.
- **HA-F5. Honest operation wants three seeds through the whole of initial sync, not only near a switch.** The ingest connects bodies under its window (one seed, two for 784 blocks after each switch) while header sync runs ahead under the frontier's seed.
- **HA-F6. The evidence check has a ruled cache of its own** (Rick, 2026-10-19; `DRS_X_STORE_FLIP.md` DX-Q2 item 6). Kept beside three others it would be a fourth; HA-R3 makes it a job inside the cap.
- **HA-F7. Three caches leave PB-R1 about 100 MiB; four exceed it.** PB-R1 is 2 GiB with mining off (`DAEMON_REDB_STORE.md` §1.3a): a 1 GiB store cache, a 64 MiB pool cache, "about 256 MiB" of RandomX and the process. The process outside the caches read about 90 MiB on regtest (RssAnon 354,624 kB with one cache, 2026-11-09). Three caches make 1,024 + 64 + 768 + 90 = 1,946 MiB. Four make 2,202 MiB. This is arithmetic from the budget row and one regtest reading, not a floor-device run at design load.
- **HA-F8. A switch prepares caches it rarely hashes under.** `prepare_all` (`span.rs:1134`) derives each branch seed a promoted run names, but the switch forms through `Recalled` (`substrate.rs:230`), which answers from the proof-of-work hash recorded when each block first arrived. Under the actor a switch asks for a cache only for a block with no recorded hash.
- **HA-F9. A run names a seed outside the window in one case: a run that begins at genesis.** Heights 1 through 2,112 hash under block 0's id, with no lag after block 0 (`seedheight`, `shekyl-difficulty/src/seed_epoch.rs:45`). A span of blocks 0 and 1 on an empty store therefore pins block 0's id while the window, read at the committed tip, names only the null seed. Past genesis a seed is first named 65 blocks above its block, and a run is at most the arrival window (32 by default, 64 at most configured), so the block is committed and the window names it. **Checked 2026-11-10** by a probe at `pin_seeds`: 29 of 479 pinned seeds in the ingest service tests were outside the window, 28 of them block 0's id against a window of the null seed alone and one a test's own synthetic seed; none of 2,518 in the loopback harness. The node connects its pinned genesis before it takes a span, so no peer can cause the case. The test is `a_run_from_genesis_hashes_under_a_seed_the_window_does_not_name`. Under HA-R1 a run is a job and the case needs no rule of its own.
- **HA-F10. The earlier "no cache store" proposal was rejected for unbounded holding** (`cache_store.rs:17–:34`; `docs/completed/RANDOMX_V2_PHASE2F_PLAN.md` §3.1 Round 2, alternatives (d) and (g)): consumers managing `Arc<PreparedCache>` themselves gave no cap. That objection does not reach this design, because the cap is the actor's and no consumer holds an `Arc`. It is the bar the lending type in §5.3 has to meet.
- **HA-F11. The evidence check has no admission rate in time.** The sync model admits one check at a time and at most one per session (`P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q2 step 3, item 3). A candidate needs a past-cap run whose cheap checks pass and whose computed work exceeds the local chain's, and timestamps raise computed work for free. What prices the next session is the clearnet reconnect throttle, which is registered and not built (`P2P_TRANSPORT_LAYER.md`, "Clearnet reconnect throttle"). So the only bound today is that checks are serial.

## 4. Rulings — RULED 2026-11-10 and 2026-11-11 (Rick)

- **HA-R1. A job gets a cache whenever it needs one.** The ranking decides only what stays warm. A job's seed comes from chain data the ingest has checked, and the actor builds it for the job's scope if it is not warm, inside the cap. A run is a job. One actor builds each seed once.
- **HA-R2. Three caches in total, jobs in flight included. It is a hard cap.** The third goes to the seed of the most-work chain the body window does not cover: the header frontier while syncing, the heaviest held fork once synced. That is one rule.
- **HA-R3. The evidence check is a job.** Jobs come before warm residency, so a check pushes out the warm third cache and cannot be starved.
- **HA-R4. One pure ranking function, tested in isolation.** Its inputs are the ingest window, the held forks and chain sync's header frontier. Its output is the one ranked list the actor receives. `Executor::branch` and the evidence check's own build are deleted and become jobs.
- **HA-R5. The actor refills when its job queue is empty.** The invariant: at quiescence it holds exactly what a fresh actor would.
- **HA-R6. The permits go behind the actor. The crate is `shekyl-hasher`. The cut is four PRs.** The crate PR's tests are the invariant tests the cutover reuses. The cutover includes the RPC's `AdmittedPow` (`read_facts.rs:127`) and the executor.
- **HA-R7 (2026-11-11). The window's pair is never freed for a job.** Jobs outside the window share the places the window leaves.
- **HA-R8 (2026-11-11). The queue for a place is first in, first out among outside-window jobs.** Class order applies to permits only. Otherwise `Class::Evidence`, the lowest class that builds, could wait behind header proofs through the whole of initial sync.

## 5. The design

One actor owns every `PreparedCache` in the process. Nothing else builds, holds or frees one.

### 5.1 The ranked list

`ranked_seeds` is a pure function in `cache_window.rs`, beside `seeds_for` and `seeds_on`. It has no clock, no actor and no I/O beyond the snapshot it is handed.

- **Inputs:** the ingest window's pair on a store snapshot; the held branch tips inside the cap with their cumulative work (`ChainStore::alt_blocks`); chain sync's header frontier, with its seed and proven work, when a run is ahead of the body window.
- **Output:** at most three seeds, in order:
  1. the connecting height's seed;
  2. the window's other seed, when it names one;
  3. the seed of the most-work chain the body window does not cover, when that seed is not already listed.

The ingest computes the list whenever one of its inputs changes, and sends it whole:

- a tip move (a connect, a pop, a switch);
- a held alternative stored or retired. Storing one does not move the tip (`switch.rs:502`, `insert_alt_block`, then `Offered::Held`), and it can change which held fork has the most work;
- chain sync's frontier moving, or its run ending.

A list computed only on tip moves would rank the forks as they stood at the last tip, and the actor would free the heaviest fork's cache at the next quiescence and rebuild it for that fork's next span. The actor knows nothing about chains.

### 5.2 What is resident

`shekyl-hasher` `core.rs` is these rules as a state machine with no clock, threads, caches or I/O. The crate's shell runs it under one lock; production runs the same core.

- **Hard cap: three places, 768 MiB** (`CAP`), counting warm caches, caches a job is hashing under, and a build reserved or in progress.
- **Warm** means resident with no job in flight. At quiescence (no job waiting or holding a lease, no build) the entries are exactly the ranked list, and a fresh hasher fed the same list reaches the same entries (HA-R5).
- **The window's places are reserved (HA-R7).** Each window seed has a place whether it is built or not, and no job frees one. Jobs outside the window share the other places: two when the window names one seed, one when it names two.
- **A window job** is granted at once when its seed is resident, waits for the build when it is building, and otherwise has its build put into the reserved place. All three places can be in use only after the list grew while outside leases were out. Then the lowest-ranked idle outside entry is freed (an unlisted one before the third); when none is idle, the window build waits for the first outside lease to come back, and no outside job takes or joins a place meanwhile.
- **An outside job (HA-R8)** joins the queue when the queue is not empty, even when its seed is resident: a stream for one seed does not pass a job waiting for another. Otherwise it joins its seed's entry, takes a free outside place, or frees the lowest-ranked idle outside entry. Otherwise it queues. Only the queue's head is ever considered, and class never moves a job in it. **The worst wait for a place is one job plus one build:** the job hashing under the place when the waiter reaches the head, then the waiter's own derivation (about 2.1 s on the floor device).
- **A warm loan** (`lend_warm`, the miner and `calc_pow`) is granted only on a listed, resident seed, and on the third only while no job queues. It never schedules a build or waits for a place. A new list that does not name its seed cancels it, and so does a job or a window build that needs its place: a warm loan never holds off a job. Its cache goes when the loan returns, after its in-flight hash. A `run` or `lend` lease is never cancelled (HA-R1).
- **Refill.** After every event: an entry nothing lists, holds or waits for is freed; a window seed with nothing reserved takes its reserved place; the third takes a free outside place only when no job queues (HA-R3); and a reserved build that has not begun, that no job waits for and that is no longer listed is dropped. A build that has begun always finishes.

### 5.3 Jobs borrow

Work reaches a cache only through a job, and **a job names one seed.** The crate's public surface has no `PreparedCache` and no `Arc` in any signature (`shekyl-hasher` `lib.rs`):

```rust
impl Hasher {
    pub fn start(budget: Budget) -> std::io::Result<(Hasher, Owner)>;
    pub fn rank(&self, list: Ranked);
    /// One permit of `class` for the whole job. Lease first, then permit.
    pub fn run<R>(&self, class: Class, seed: Seedhash, stop: &AtomicBool,
                  job: impl for<'job> FnOnce(&Lent<'job>) -> R) -> Option<R>;
    /// No permit for the job: each `Loan::hash` takes one of `class`.
    pub fn lend<R>(&self, class: Class, seed: Seedhash, stop: &AtomicBool,
                   job: impl for<'job> FnOnce(&Loan<'job>) -> R) -> Option<R>;
    /// `lend` that builds nothing and never waits for a place.
    pub fn lend_warm<R>(&self, class: Class, seed: Seedhash, stop: &AtomicBool,
                        job: impl for<'job> FnOnce(&Loan<'job>) -> R) -> Result<R, Declined>;
    pub fn wake(&self);
    pub fn resident(&self) -> tokio::sync::watch::Receiver<Resident>;
}
impl Lent<'_> { pub fn hash(&self, blob: &[u8]) -> [u8; 32]; }
impl Loan<'_> { pub fn hash(&self, blob: &[u8]) -> Result<[u8; 32], Unhashed>; }
```

- **One seed per job:** `hash` takes no seed, so no job can ask for one it did not name. A switch lends once per contiguous run of its heights' seeds (§6 step 3).
- `Lent` and `Loan` hand out hashes, never the cache, and neither is `Clone`. Both are `Sync`, so a job can share them across `std::thread::scope` threads inside its closure. `tests/trybuild.rs` holds that a job cannot return one, store one outside itself, or clone one.
- The `for<'job>` bound means `R` cannot name the job's lifetime, so a `Lent` or `Loan` cannot be returned or stored.
- **No nested jobs.** A job that asks for another job while it holds one could wait for a place behind itself, so `run`, `lend` and `lend_warm` panic when called from inside a job's closure on the same thread. A thread the job spawns inside its closure is not covered.
- **`Loan::hash`** checks its cancel flag, takes a permit of the job's class with the caller's stop flag, checks the cancel flag again, and hashes. `Unhashed::Cancelled` is only for a warm loan; `Unhashed::Stopped` is the caller's stop.
- **`wake`** takes the lock before it notifies, as `Budget::wake` does, so it cannot land between a waiter's stop check and its wait; it also wakes the budget.
- `run` blocks its caller: it takes the lease (waiting for a build or a place), then the permit, then calls `job` on the caller's thread. Callers already wait for permits on blocking threads (`span.rs:418`), so the node's thread count (`shekyl-node/src/lib.rs`, "Blocking threads") stands.
- **How a form gets its hash.** The ingest's substrate becomes a struct over a `&Lent` and the clock. `Substrate::longhash` stays synchronous and calls `lent.hash`. `form_on_branch` (`span.rs:977`) and `spawn_form` (`:294`) each become one `run` whose closure builds that substrate and calls `form`. This fits both as they are: each already runs one `form` inside one blocking closure that holds one permit.
- **Two entry points, because permits are held two ways today.** `run` holds one permit for the job, which is one form. `lend` holds no permit for the job and takes one inside each `Loan::hash`, of the job's class. A job that hashes on several threads, or many times, uses `lend`: a switch, a header-proof command (`executor.rs:238`, one permit an item across the budget's lanes), the evidence check.
- **A switch uses `lend`, not `run`.** `form_switch` (`span.rs:1163`) forms a plan on as many threads as the budget has permits, and each block takes its own permit through a callback (`plan_form.rs:179`). Wrapped in `run`, the job would hold the one permit of a one-permit budget while its workers waited for another: a deadlock. Without the callback, its workers would hash side by side under one permit. Under `lend` the callback goes and the permit is taken where the hash is, so a promoted block answered from its recorded hash (HA-F8) takes none.
- **Jobs that build:** a run's forms, an alternative's form, a switch's forms for a block with no recorded hash (HA-F8), chain sync's header proofs on any seed, and the evidence check. Each names a seed the ingest or the sync model took from checked chain data.
- **Jobs that do not build:** the miner and `calc_pow`. An RPC caller names `calc_pow`'s seed, so it hashes only under a warm cache (ruled 2026-10-17, `read_facts.rs:108–:112`); the miner's seed is the template's, which the follower posts only when it is warm. Their entry points return "not warm" and build nothing. The miner's is `lend` without the build: it lends for the posted job's life, takes one `Class::Miner` permit per hash as `miner.rs:327` does now, and carries a cancel flag the actor sets when the seed leaves the list.

### 5.4 Permits

The permits are taken inside the actor's entry points, lease first, then permit. `Budget` keeps its type and its class rules; no consumer holds one.

- A caller that held a permit while waiting for a cache would wait on a build that needs a permit. On a one-permit budget that never ends. Today the order "gate, permit, `pin_lock`" is a comment each call site obeys (`service.rs:555–:568`).
- A refill has no caller thread, so the actor takes that build's permit itself. **A refill is paid at the class of what caused it:** the class of the job that pushed the cache out, or, when the list changed with no job (a new tip, a new heaviest fork), `Class::Chain` for the window's pair and the class of that chain's own jobs for the third. So a low-class job cannot buy a higher-class build: the refill after an evidence check is an `Evidence` build. A job that arrives for the seed while its refill waits builds it under the job's own class, or the refill's when that is higher.
- **The class rise.** One builder thread (`shekyl-hasher-build`, a dedicated thread in the process's thread ledger, outside the runtime's blocking pool) takes the next build and a permit of its class, with a per-build flag as the permit wait's stop. When a job raises that build's class, or the next build changes, the core sets the flag and wakes the budget: the wait ends, and the builder asks again at the new class. A low-class job cannot buy a high-class build, and a high-class job is not held behind a low-class wait.
- The branch gate (`service.rs:568`) goes: it bounded live caches to three, and the cap does that now.

### 5.5 Builds and the order

The actor's loop only takes lists, grants and releases leases, and queues builds. It never hashes and never derives. One builder thread derives one cache at a time.

- **Order:** a waiting job's seed before any refill; among jobs, the order they took their places in (§5.2); among refills, by rank. Hasher class orders permits and nothing else.
- **The canonical seed is known 64 blocks before it is used,** because the window names a seed once its block is on the chain. It is built then, so a chain form waits for a build only at a cold start or after a reorg that replaces the seed block.
- **A running build is not interrupted.** The derivation work ahead of a chain form is at most one build in progress plus its own: two derivations, about 4.2 s on the floor device.
- **That is not the whole wait.** The cap counts jobs in flight (HA-R2), so a build also waits for a place when all three are in use and none can be freed. For a chain form that needs a new canonical seed, that is a reorg that replaces the seed block while the third place has a job in flight and the old canonical cache is still hashed under. The wait is then the rest of one job: a form, one header-proof command, or one miner hash, and a miner hash at nice 19 can take about a minute on the floor device (`shekyl-hash-budget`'s module docs). The permit wait is on top, as it is today. So the bound on a chain form's wait is two derivations, one job's remainder, and its permit.

### 5.6 Publication

The actor publishes `Resident` on a watch after every change: each place's seed and whether it is `Warm`, `Leased` or `Building`, with the count of builds and their total time. Its length is the live-cache count the memory budget is checked against (PB-R1). In §6 step 3 it replaces `Door::seeds`, `published_seeds`, `seed_now` and `seed_pair`: the follower posts a template when the canonical seed is warm, a span waits for it before its first hash, and `builds` replaces the ingest's `timed_derive` count. Chain sync no longer waits on a seed it found absent: its proofs are jobs, and `Proved::NotHeld` and `Command::SeedNotHeld` go.

### 5.7 Stop

Each caller passes its own stop flag, as it passes one to `Budget::acquire_unless` today, so the node's stop order (`shekyl-node/src/lib.rs`, "Stop") is unchanged through step 6. A set flag ends that caller's waits and refuses its next job; a hash in progress finishes. The actor is built before every consumer and stopped after the miner drains (step 7). `Owner::stop` refuses new jobs, wakes every waiter, waits for every lease out to return, lets a running derive finish, frees every cache and joins the builder. Dropping the `Owner` stops it too.

The crate has no end of its own, so it has no `NodeEnd` variant: `PreparedCache::derive` is infallible, an allocation failure aborts, both production profiles abort on panic, and the list arrives by method call, not a channel, so no input can close (rule 25 covers a task that can end on its own).

### 5.8 The bound, and what a rebuild costs

- **The window names at most two seeds.** It is `cap + max(cap, 65)` wide, 1,440 blocks at the production cap, inside one 2,048-block epoch; a compile-time assertion holds `D_MAX` to that (`cache_window.rs:41`).
- **A fork across two seed boundaries is not excluded by the code.** A held fork's root is within the cap below the tip (the death rule, `alt.rs:265`), but nothing bounds how far above the tip it reaches. The design does not depend on it: the list names one seed for the most-work chain, and a job names its own.
- **Three is routine** through initial sync (HA-F5).

**Measured 2026-11-10 on the floor device** (Pi 4, `dev` at `cf561f79d6`, the Release `cache_derive` bench, 100 samples a run, the device's resident testnet daemon running throughout at about 188 % CPU):

| run | low | median | high |
| --- | --- | --- | --- |
| 1 | 2.0900 s | 2.0946 s | 2.0994 s |
| 2 | 2.1118 s | 2.1149 s | 2.1181 s |
| 3 | 2.0926 s | 2.0971 s | 2.1021 s |

- One forced rebuild costs about **2.1 s** of one core on the floor device, 6.1 times the 341 ms x86 figure (`rust/shekyl-pow-randomx/BENCH_RESULTS.md`).
- The readings were taken beside a busy node, which is the condition a forced rebuild meets. They are not an idle-device figure.
- The record is `docs/benchmarks/cache_derive_pi4_20261110.txt`, with its environment in `cache_derive_pi4_20261110_env.tsv`.
- The derive is a row of the bench suite: `cache_derive_iai` (`hot_path_bench_cache_derive`, instructions, slowdown-only) beside the criterion `cache_derive`, registered in `scripts/bench/capture_rust_baseline.sh`.

### 5.9 The evidence check's worst case

- **The admission rate:** one check at a time, and at most one per session (HA-F11). There is no rate in time.
- **What one check costs this node:** its own build, and the refill of the warm third cache it pushed out: two derivations, about 4.2 s of one core on the floor device. Both are `Class::Evidence` builds (§5.4: a refill is paid at the class of what caused it), which every class but the miner outranks.
- **The worst case an attacker can force** is therefore one permit kept building for as long as the attacker can open sessions that pass the cheap checks. Checks are serial, so it is never more than one build at a time, and the window's pair is never touched.
- **Accepted as the bound for now (Rick, 2026-11-11).**
- **What closes it:** the clearnet reconnect throttle, `P2P_TRANSPORT_LAYER.md` § "Clearnet reconnect throttle — REGISTERED 2026-10-09, not built" (ruling D-S1; owner: the transport layer, that document). Its `N` handshakes per `T` gives the rate, and this section then states `N / T × 4.2 s`. It is on the mainnet launch checklist (`docs/RELEASE_CHECKLIST.md`) and has a `docs/FOLLOWUPS.md` row.

## 6. The PR sequence — RULED (HA-R6)

1. **This document.**
2. **`shekyl-hasher`, with no consumer** (rule 26: a new crate is its own PR) — BUILT (as of 2026-11-12). The actor, the cap, leases, builds, refill and the metric. Its tests are the invariant tests of §8, written against the crate's own API so the cutover reuses them. The floor derive bench joins the bench suite here. Nothing calls the crate until step 3: that is the staged build, not a defect.
3. **The cutover, one PR, driven by the deletion.** The cache store's slots are shared by every consumer in §2, so any split leaves two owners of caches in one process. This PR deletes the slot API and moves the ingest, chain sync's executor, the miner, `calc_pow` and its `AdmittedPow`, the node, the replay binary, the pipeline and the test harnesses onto the actor, with `ranked_seeds` and its tests.
4. **Close-out.** The live RSS capture repeated with a fork case, PB-R1's cache rows restated against the cap, and this document moved or made a contract (rule 95).

## 7. What it deletes

- **In `shekyl-pow-randomx`:** the two slots and `lookup`, `lookup_or_derive`, `pin_canonical`, `set_canonical`, `release` and `slots` (`cache_store.rs:443–:651`). The derivation de-duplication moves into the actor, its only caller. `PreparedCache::derive` stays `pub`, because the actor lives above this crate (the crate is held to isolation invariants "a scheduler has no business under", `shekyl-hash-budget/Cargo.toml`); a gate holds its callers to the actor, the benches and the differential harness.
- **In `shekyl-chain-rules`:** `pin_seed`, `release_seed`, `slots`, `prepare_seed`, `cache_absent`, `longhash_held` and `type Held` on `Substrate`.
- **In `shekyl-chain-ingest`:** `pin_lock` and the installed-window record; `published_seeds`, `seed_now` and `seed_pair`; `install_blocking`, `install_pair`, `window_is_settled`, `with_pin_lock` and `pin_view` (`window.rs`); `pin_seeds` and both `prepare_seed` sites (`span.rs`); `SlotPair`; the branch gate; `Branch` (`substrate.rs:308–:365`); `ProductionSubstrate`'s `Arc<CacheStore>` and `SubstrateFault::CacheAbsent`.
- **In `shekyl-chain-sync-runtime`:** `Executor::branch`, `branch_held`, `branch_cache`, `derive`, `Prepared` and `HeldSubstrate` (`executor.rs:54`, `:101–:120`, `:184–:217`, `:302–:338`), the executor's own `Budget`, and the owner's wait on the seeds watch (`owner.rs:541`, `:1321`).
- **In `shekyl-chain-sync`:** `CachePlan`'s three-way split as a cache choice, `Proved::NotHeld` and `Command::SeedNotHeld`. Whether a seed is earned stays the model's.
- **In `shekyl-miner`:** the `caches.lookup` at `miner.rs:308`.
- **In `shekyl-daemon-rpc`:** `store_facts.rs:161`'s `Arc<CacheStore>` and `AdmittedPow`'s `Arc<PreparedCache>` (`read_facts.rs:127`).
- **In `shekyl-node`:** `lib.rs:283` builds the actor; `mining.rs:207`'s `Arc<CacheStore>` goes.
- **Tools and tests** in §2's last row take the actor, and `the_record_is_the_slots` and the `Gated` substrate's slot model go: with the slot API gone there is no second pathway to leave them on.

## 8. Tests

- **`ranked_seeds`, in isolation:** table tests over the window's one-seed and two-seed spans, a held fork past its seed point, two held forks (the heavier is listed), a header frontier ahead of the window, a frontier and a fork together (the more work is listed), and a seed already in the window (not listed twice).
- **The invariant (HA-R5):** after any sequence of blocks, forks, reorgs, pops, header runs and evidence checks, once the actor is quiet it holds exactly the caches a fresh actor would hold for the same list. *Always*, quiet or not: no more than three caches exist. Run after every reply in the connect-path tests.
- **Red first, each failing on `dev` at `cf561f79d6`:**
  - a fork past its seed point whose tip then leaves the cap: its cache is gone at the next quiescence;
  - a second span of a live fork: nothing is built;
  - a header run across a seed boundary that then ends: its cache is freed (HA-F1);
  - a fork whose headers were proven and whose bodies then arrive: one build (HA-F2);
  - a switch whose promoted blocks all have recorded hashes: no build (HA-F8);
  - an evidence check while the third cache is warm: the check runs, the warm cache is freed for it, and it is back at quiescence (HA-R3);
  - an evidence check queued behind a stream of header-proof jobs for another seed: it runs after the one job ahead of it, not after the stream (HA-R8);
  - two outside-window jobs while the window names two seeds: neither frees a window seed (HA-R7);
  - a mining job whose seed leaves the list: the job is cancelled and the cache freed;
  - `calc_pow` on a seed that is not warm: declined, nothing built.
- **Carried over from #1338:** the 2,124-block nightly test, and the live RSS reading (shekyl-dev `infrastructure/captures/a2-randomx-cache-rss/2026-11-09/`), repeated on the new build with a fork case added.
- **A metric:** the count of live caches, exported, so a node's memory can be checked against PB-R1.
- **A gate** holds `PreparedCache::derive` and `Arc<PreparedCache>` to the paths in §7, and asserts those paths exist (rule 47).

## 9. Wargame

- **Forced rebuilds.** A warm cache is free to hash under, so an attacker gains nothing from blocks on the most-work fork or the frontier. A block on a lighter held fork past its seed point (66 blocks of real work behind it: the seed block and the 65 above it) costs this node that fork's build and one refill, about 4.2 s on the floor device, both under the arrival's class (§5.4).
- **The evidence check.** §5.9.
- **Evicting the window's pair.** It cannot be done (§5.2).
- **Initial sync against a cheap fork.** Early blocks are cheap, so a forged run of 65 early headers earns a seed cheaply. Its proofs are jobs and get their cache; it does not hold the warm third place, which goes to the most proven work.
- **A lent cache held too long.** §5.3's types. An `Arc<PreparedCache>` outside the crate fails the gate in §8.
- **The actor stalling.** §5.5: the loop itself never hashes or derives; what a job can wait for is stated there.
- **Shutdown.** §5.7.

## 10. What this round read, and what it did not

Read at `cf561f79d6`: `cache_store.rs` (the store and its header), both `substrate.rs` files, `cache_window.rs`, `window.rs`, `span.rs`'s run, alternative and switch paths, `service.rs`'s shared state and stop, `executor.rs` whole, `peer.rs:631–:664`, the miner's work loop, `calc_pow`'s admission, the node's composition and stop order, `shekyl-hash-budget`'s header, and CS-Q2 step 3 and DX-Q2 items 1 and 6.

Not read: `switch.rs` and `plan_form.rs` beyond their call sites, the sync owner past its seed wait, the scenario harness beyond its pin sites, and `shekyl-randomx-differential`. No fleet node was read for HA-F1; the finding is from the code.
