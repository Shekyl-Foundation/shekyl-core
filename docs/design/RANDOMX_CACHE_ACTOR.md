# One hashing actor owns the RandomX caches

**Status:** OPEN — Round 0 RULED 2026-11-10 and 2026-11-11 (Rick): HA-R1…HA-R8, §4. §6 steps 2 and 3 BUILT (as of 2026-11-14): the crate `rust/shekyl-hasher`, and the cutover that moved every consumer onto it and deleted the cache store. Step 4, the close-out, is next.

**Ground:** the cutover's own tree, branched from `dev` at `bfdc84a30e` (which includes #1327 and #1359). §2 and §5 describe that tree. §1 and §3 are the findings as they were read at `cf561f79d6`, before the cutover: each names the code it found, which the cutover deleted.

**Identifiers:** `HA-F*` are this round's findings, `HA-R*` its rulings.

## 1. The problem is a class

A RandomX cache is 256 MiB. Today a cache stays resident until someone remembers to release it, and four times nobody did:

1. **A2 (alpha.11).** The previous epoch's cache stayed resident after the window stopped naming it.
2. **#1301.** Its release never ran on a live node, because a published record of the slots had drifted from the slots. #1338 fixed that.
3. **The fork seed (on `dev`).** A branch form prepares a fork's own seed into the second slot (`span.rs:993`, `:1149`). No window names that seed, so nothing releases it before the next epoch's pin.
4. **Chain sync's branch cache (on `dev`, HA-F1).** The header executor keeps one cache of its own outside the store, and nothing drops it (§3).

Each fix so far made the bookkeeping more careful. This design removes the bookkeeping: one owner holds every cache, and what it holds is computed from what the node needs.

## 2. Who touches a cache

One crate builds, holds and frees a `PreparedCache`: `shekyl-hasher`. Every other consumer hashes through a job on the node's one `Hasher` and holds no cache and no budget. `scripts/ci/check_randomx_cache_owner.sh` holds `PreparedCache::derive` and `Arc<PreparedCache>` to the paths in the last two rows.

| Consumer | Where | How it hashes |
| --- | --- | --- |
| The node | `shekyl-node/src/lib.rs` (`Node::open`, `Node::stop`) | starts the hasher over the budget, hands it out, stops it last |
| Ingest: a form | `shekyl-chain-ingest/src/span.rs` (`spawn_form`) | one `run` job on the block's claimed seed |
| Ingest: an alternative's form | `span.rs` (`offer_alt`) | the same job, on the branch's seed |
| Ingest: a switch | `plan_form.rs` (`form_plan`) | one `lend` job per run of blocks under one seed; none for a run whose hashes are all recorded |
| Ingest: the ranker | `window.rs` (`rank`), `cache_window.rs` (`ranked_on`) | hashes nothing; sends the ranked list |
| Ingest: the tip follower | `follower.rs` | hashes nothing; reads `Resident` for the template's seed |
| Ingest: the replay pipeline | `pipeline.rs` | one `run` job a block, on a hasher of the tool's own; it ranks the seed it forms under |
| Chain sync: header proofs and the evidence check | `shekyl-chain-sync-runtime/src/executor.rs` (`prove`) | one `lend` job a command, on the command's seed |
| The miner | `shekyl-miner/src/miner.rs` (`work`) | one `lend_warm` loan a posted job |
| `pow` (the RPC) | `shekyl-daemon-rpc/src/store_read_facts.rs` (`pow`) | one `lend_warm` loan a request |
| The owner | `rust/shekyl-hasher/src` | builds, holds, lends, frees |
| The verifier, its benches and example, the differential harness's parity and corpus modes, the block-connect cost bench | `shekyl-pow-randomx/{src,benches,examples}`, `shekyl-randomx-differential`, `shekyl-verify-cost/benches` | derive a cache directly: they measure or compare the verifier, and never run in the daemon |

The ingest reaches the hasher through one boundary, `Pow` (`shekyl-chain-ingest/src/pow.rs`): `run`, `lend`, `rank`, `wake`, and the seed's readiness. Production plugs in `ProductionPow` over the `Hasher`; a feature test plugs in a fixture that is its own job and holds no cache. The two differ only in the type plugged in.

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

`ranked_seeds` is a pure function in `cache_window.rs`, beside `seeds_on`. It has no clock, no actor and no I/O. A gather step (`gather`) reads one store snapshot into the plain values it takes; `ranked_on` is the two together.

- **Inputs:**
  - the window's pair at the tip (`seeds_on`);
  - each held fork tip inside the cap (`ReadSnapshot::alternate_chains`), as the seed its next block hashes under and its cumulative work. That seed is the main chain's block when the seed height is at or below the fork point, and otherwise the fork's own block;
  - chain sync's header frontier, when its owner has published one: the seed and the proven work of the run with the most proven work (`Sync::frontier`). Evidence runs are not counted (HA-R3).
- **Output:** at most three seeds, in order:
  1. the connecting height's seed;
  2. the window's other seed, when it names one;
  3. the seed of the most-work chain among the held forks and the frontier, when the window does not already name it. When it does there is no third: the next-heaviest chain does not take the place (HA-R2's one rule).
- **Equal work** is decided by a fixed order: a held fork before the frontier, and between forks the first in the alt table's key order.
- **The third's class** is the class its jobs hash at: `HeaderPow` for the frontier, `Unsolicited` for a held fork, which is lighter than the main chain and reaches this node as announcements.
- **A store with no block ranks nothing,** so the list never names the null seed. Genesis is still hashed under it: its form is a job, which builds the null seed's cache in an outside place, and refill frees it at the next quiescence. A fresh store therefore derives twice (the null seed, then block 0's id) and keeps one cache. A restart derives once.
- **A fully proven run offers its last seed.** A run with every header proven has no next proof yet, and its next headers most likely hash under the seed its last header named. The model offers that seed, so the cache is not freed between one response's headers and the next's. A run with nothing proven offers nothing.

One task in the ingest service computes the list and sends it whole: the ranker (`window.rs`, `rank`). It is woken by a `Notify` and by the frontier watch, and each wake reads a fresh snapshot, so the last list sent is always from the newest one.

- **The connector wakes it** after every write that can change the list: a tip move (a connect, a pop, a switch), and an alternative stored, promoted, refused or retired. Storing an alternative does not move the tip, and it can change which held fork has the most work.
- **The frontier wakes it** when chain sync's owner publishes a new value. The node makes the channel before either service starts; the ingest holds the receiver and the owner the sender, and neither service calls the other. When the sender closes, the owner has ended or stopped: the ingest ranks with no frontier from then on, and that is not a fault in the ingest.
- **The tip follower asks for a ranking and waits for it** before it builds a template. The miner's warm loan is granted only on a listed seed, so the list names the new tip's seed before a job on it is posted.

A list computed only on tip moves would rank the forks as they stood at the last tip, and the actor would free the heaviest fork's cache at the next quiescence and rebuild it for that fork's next span. The actor knows nothing about chains.

### 5.2 What is resident

`shekyl-hasher` `core.rs` is these rules as a state machine with no clock, threads, caches or I/O. The crate's shell runs it under one lock; production runs the same core. What the core returns is a command: drop a cache, cancel a warm lease, or wake the builder off its permit wait. A grant and a reserved build are state. The waiting thread and the builder read them after that wake.

- **Hard cap: three places, 768 MiB** (`CAP`), counting warm caches, caches a job is hashing under, a build reserved or in progress, and a freed cache not yet dropped. The cap is the memory, not the core's count.
- **A freed place is free once its memory is.** Freeing a cache moves its entry to *retiring*: it keeps its place, is never granted and never rebuilt. The shell drops the cache with no lock held, asserts it was the last holder (every build, including release), then reports the drop (`Core::retired`), and only then is the place free. The step that frees a place never takes it; the settle after the drop does. A request drops what it freed before it waits for its grant, so its own build never waits on its own drop.
- **Warm** means resident with no job in flight. At quiescence (no job waiting or holding a lease, no build) the entries are exactly the ranked list, and a fresh hasher fed the same list reaches the same entries (HA-R5).
- **The window's places are reserved (HA-R7).** Each window seed has a place whether it is built or not, and no job frees one. Jobs outside the window share the other places: two when the window names one seed, one when it names two.
- **A window job** is granted at once when its seed is resident, waits for the build when it is building, and otherwise has its build put into the reserved place. All three places can be in use only after the list grew while outside leases were out. Then the lowest-ranked idle outside entry is freed (an unlisted one before the third); when none is idle, the window build waits for the first outside lease to come back, and no outside job takes or joins a place meanwhile.
- **An outside job (HA-R8)** joins the queue when the queue is not empty, even when its seed is resident: a stream for one seed does not pass a job waiting for another. Otherwise it joins its seed's entry, takes a free outside place, or frees the lowest-ranked idle outside entry and queues for that place until the cache is dropped. Otherwise it queues. Only the queue's head is ever considered, and class never moves a job in it. **The worst wait for a place is one job plus one build:** the job hashing under the place when the waiter reaches the head, then the waiter's own derivation (about 2.1 s on the floor device).
- **A warm loan** (`lend_warm`, the miner and `calc_pow`) is granted only on a listed, resident seed, and on the third only while nothing waits for a place: no job queues and no window seed is short of one. A loan there would hold the place they wait for, and overlapping loans would hold it for ever. It never schedules a build or waits for a place. A new list that does not name its seed cancels it, and so does a job or a window build that needs its place: a warm loan never holds off a job. A cancel ends the loan's permit wait at once. Its cache goes when the loan returns, after its in-flight hash. A `run` or `lend` lease is never cancelled (HA-R1).
- **Refill.** After every event: an entry nothing lists, holds or waits for is freed; a window seed with nothing reserved takes its reserved place; the third takes a free outside place only when no job queues (HA-R3); and a reserved build that has not begun, that no job waits for and that is no longer listed is dropped. A build that has begun always finishes. Each event settles to a fixpoint within a bound; a settle that runs out of passes still moving panics with that invariant's name rather than leaving a waiter nothing wakes.

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
    pub fn permits(&self) -> usize;
    pub fn resident(&self) -> tokio::sync::watch::Receiver<Resident>;
}
impl Lent<'_> { pub fn hash(&self, blob: &[u8]) -> [u8; 32]; }
impl Loan<'_> {
    pub fn hash(&self, blob: &[u8]) -> Result<[u8; 32], Unhashed>;
    /// `hash`, with how long RandomX itself ran: the permit wait is not in it.
    pub fn hash_timed(&self, blob: &[u8]) -> Result<([u8; 32], Duration), Unhashed>;
}
```

- **One seed per job:** `hash` takes no seed, so no job can ask for one it did not name. A switch lends once per contiguous run of its blocks' claimed seeds (`plan_form.rs`). The ingest's job substrate checks the seed the rule names against the job's: a mismatch is the fault `SeedNotLent`, a caller's defect that stops the service and is never a verdict on the block.
- **`permits`** is the budget's permit count, for a consumer that sizes its lanes by it: a consumer holds no budget to read it from. **`hash_timed`** lets a caller that measures the verifier time the hash apart from the permit wait.
- `Lent` and `Loan` hand out hashes, never the cache, and neither is `Clone`. Both are `Sync`, so a job can share them across `std::thread::scope` threads inside its closure. `tests/trybuild.rs` holds that a job cannot return one, store one outside itself, or clone one.
- The `for<'job>` bound means `R` cannot name the job's lifetime, so a `Lent` or `Loan` cannot be returned or stored.
- **No nested jobs.** A job that asks for another job while it holds one could wait for a place behind itself, so `run`, `lend` and `lend_warm` panic when called from inside a job's closure on the same thread. A thread the job spawns inside its closure is not covered.
- **`Loan::hash`** checks its cancel flag, takes a permit of the job's class, checks the cancel flag again, and hashes. A warm loan's permit wait ends on either the caller's stop or its cancel (`Budget::acquire_unless_either`), and a cancel wakes the budget: a cancelled loan parked for a permit returns at once instead of holding its place until a permit reaches its class. `Unhashed::Cancelled` is only for a warm loan, and is reported when both are set; `Unhashed::Stopped` is the caller's stop.
- **Never ask for a job while holding a permit.** The builder takes a permit to build the cache a job waits for; on a one-permit budget the caller's own permit is that permit. The crate cannot see it, because a permit belongs to no thread, so `run`, `lend` and `lend_warm` say so under *Deadlock*. It is structural: every consumer takes its permits only through the hasher, and none holds a budget.
- **`wake`** takes the lock before it notifies, as `Budget::wake` does, so it cannot land between a waiter's stop check and its wait; it also wakes the budget.
- `run` blocks its caller: it takes the lease (waiting for a build or a place), then the permit, then calls `job` on the caller's thread. A form's job waits on a blocking thread. A span sends its next form only once the previous one's job was granted, so each span has at most one ungranted form on a thread, and granted forms hold a permit: the node's blocking pool is sized permits + window + 1 from those two bounds (`shekyl-node/src/lib.rs`, "Blocking threads").
- **How a form gets its hash.** The ingest's job substrate is a struct over a `&Lent` (or a `&Loan`) and the clock (`pow.rs`). `Substrate::longhash` is synchronous and calls `lent.hash`. A form on the tip and a form on a branch are the same thing: one `run` job whose closure is handed that substrate and calls `form` (`span.rs`, `spawn_form`).
- **Two entry points, because permits are held two ways.** `run` holds one permit for the job, which is one form. `lend` holds no permit for the job and takes one inside each `Loan::hash`, of the job's class. A job that hashes on several threads, or many times, uses `lend`: a switch, a header-proof command (`executor.rs`, `prove`: one permit an item across as many scoped lanes as there are permits), the evidence check.
- **A switch uses `lend`, not `run`.** `form_plan` forms a run of the plan on as many threads as the hasher has permits. Wrapped in `run`, the job would hold the one permit of a one-permit budget while its workers waited for another: a deadlock. Under `lend` the permit is taken where the hash is, so a block answered from its recorded hash (HA-F8) takes none. A run whose every block was recorded under the seed it claims asks for no job at all, so such a switch builds nothing.
- **Jobs that build:** a run's forms, an alternative's form, a switch's forms for a block with no recorded hash (HA-F8), chain sync's header proofs on any seed, and the evidence check. Each names a seed the ingest or the sync model took from checked chain data.
- **Jobs that do not build:** the miner and `pow` (the RPC's `calc_pow`). An RPC caller names `pow`'s seed, so it hashes only under a warm cache (ruled 2026-10-17); the miner's seed is the template's, which the follower posts only when it is listed and warm. Their entry point, `lend_warm`, returns "not warm" and builds nothing. The miner lends for the posted job's life, takes one `Class::Miner` permit per hash, and leaves the job when the hasher cancels the loan because the seed left the list. `pow` spends the caller's RPC hash budget inside the loan, so a bounded caller pays only for a seed that was granted, and before the hash.

### 5.4 Permits

The permits are taken inside the actor's entry points, lease first, then permit. `Budget` keeps its type and its class rules; no consumer holds one.

- A caller that held a permit while waiting for a cache would wait on a build that needs a permit. On a one-permit budget that never ends. It is the *Deadlock* contract of §5.3, and no consumer holds a permit of its own.
- A refill has no caller thread, so the actor takes that build's permit itself. **A refill is paid at the class of what caused it:** the class of the job that pushed the cache out, or, when the list changed with no job (a new tip, a new heaviest fork), `Class::Chain` for the window's pair and the class of that chain's own jobs for the third. So a low-class job cannot buy a higher-class build: the refill after an evidence check is an `Evidence` build. A job that arrives for the seed while its refill waits builds it under the job's own class, or the refill's when that is higher.
- **The class rise.** One builder thread (`shekyl-hasher-build`, a dedicated thread in the process's thread ledger, outside the runtime's blocking pool) takes the next build and a permit of its class, with a per-build flag as the permit wait's stop. When a job raises that build's class, or the next build changes, the core sets the flag and wakes the budget: the wait ends, and the builder asks again at the new class. A low-class job cannot buy a high-class build, and a high-class job is not held behind a low-class wait.
- The ingest has no branch gate: the cap bounds the live caches.

### 5.5 Builds and the order

The actor's loop only takes lists, grants and releases leases, and queues builds. It never hashes and never derives. One builder thread derives one cache at a time.

- **Order:** a waiting job's seed before any refill; among jobs, the order they took their places in (§5.2); among refills, by rank. Hasher class orders permits and nothing else.
- **The canonical seed is known 64 blocks before it is used,** because the window names a seed once its block is on the chain. It is built then, so a chain form waits for a build only at a cold start or after a reorg that replaces the seed block.
- **A running build is not interrupted.** The derivation work ahead of a chain form is at most one build in progress plus its own: two derivations, about 4.2 s on the floor device.
- **That is not the whole wait.** The cap counts jobs in flight (HA-R2), so a build also waits for a place when all three are in use and none can be freed. For a chain form that needs a new canonical seed, that is a reorg that replaces the seed block while the third place has a job in flight and the old canonical cache is still hashed under. The wait is then the rest of one job: a form, one header-proof command, or one miner hash, and a miner hash at nice 19 can take about a minute on the floor device (`shekyl-hash-budget`'s module docs). The permit wait is on top, as it is today. So the bound on a chain form's wait is two derivations, one job's remainder, and its permit.

### 5.6 Publication

The actor publishes `Resident` on a watch after every change: each place's seed and whether it is `Warm`, `Leased`, `Building` or `Retiring` (freed, its cache being dropped), with the count of builds and their total time.

- **The live-cache count is its length,** which the memory budget is checked against (PB-R1). `daemon_status` reports it as `randomx_caches`, in the part shown to `status`, beside `data_size`: the node's status facts read the watch when the call is made, and nothing else counts caches. A caller without the grant gets no part.
- **The tip follower reads it for the template's seed.** A seed is ready when its place is `Warm` or `Leased`. The follower first has the list name the tip's seeds (§5.1), then builds; when the build finds the seed still building it leaves the current job and waits on the watch for that seed, and builds again when it is built. It waits on the watch only then: a `Resident` change is every lease taken and returned.
- **`builds` and `build_ns` are the one source of derive counts.** The ingest's metrics sink counts hashes and each job's wait for its lease, and its artifact reads the derives from here.
- **Nothing waits on a seed it found absent.** A span's forms and chain sync's proofs are jobs, and a job waits for its own build.

### 5.7 Stop

Each caller passes its own stop flag. A set flag ends that caller's waits and refuses its next job; a hash in progress finishes. A consumer's stop sets its flag and calls `wake`, so a job parked for a cache or a permit reads the flag at once.

The node starts the hasher before every consumer and stops it last (`shekyl-node/src/lib.rs`, "Stop", step 8): after the runtime is down and the miner drained, every job, loan and form has ended, so the stop waits on none. `Owner::stop` refuses new jobs and drops every request not yet granted: its caller returns stopped, and a build that finishes later grants nothing, so no job starts during a stop. A lease already granted stands, and the stop waits for it to return. It lets a running derive finish, frees every cache, waits for each to be dropped, and joins the builder. Dropping the `Owner` stops it too.

The crate has no end of its own, so it has no `NodeEnd` variant: `PreparedCache::derive` is infallible, an allocation failure aborts, both production profiles abort on panic, and the list arrives by method call, not a channel, so no input can close (rule 25 covers a task that can end on its own).

### 5.8 The bound, and what a rebuild costs

- **The window names at most two seeds.** It is `cap + max(cap, 65)` wide, 1,440 blocks at the production cap, inside one 2,048-block epoch; a compile-time assertion in `cache_window.rs` holds `D_MAX` to that.
- **A fork across two seed boundaries is not excluded by the code.** A held fork's root is within the cap below the tip (the store's death rule for alternatives), but nothing bounds how far above the tip it reaches. The design does not depend on it: the list names one seed for the most-work chain, and a job names its own.
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
- The derive is a row of the bench suite: `cache_derive_iai` (`hot_path_bench_cache_derive`, case `fixed_seed`, instructions, slowdown-only) beside the criterion `cache_derive`, registered in `scripts/bench/capture_rust_baseline.sh`. The named case gives the row a run id: without one gungraun prints a header the capture's parse did not read, and #1359's first capture dropped the row unseen. The parse (`scripts/bench/iai_parse.py`) now refuses such a header, a registered row whose section yields no entry, and a registered row with no section.

### 5.9 The evidence check's worst case

- **The admission rate:** one check at a time, and at most one per session (HA-F11). There is no rate in time.
- **What one check costs this node:** its own build, and the refill of the warm third cache it pushed out: two derivations, about 4.2 s of one core on the floor device. Both are `Class::Evidence` builds (§5.4: a refill is paid at the class of what caused it), which every class but the miner outranks.
- **The worst case an attacker can force** is therefore one permit kept building for as long as the attacker can open sessions that pass the cheap checks. Checks are serial, so it is never more than one build at a time, and the window's pair is never touched.
- **Accepted as the bound for now (Rick, 2026-11-11).**
- **What closes it:** the clearnet reconnect throttle, `P2P_TRANSPORT_LAYER.md` § "Clearnet reconnect throttle — REGISTERED 2026-10-09, not built" (ruling D-S1; owner: the transport layer, that document). Its `N` handshakes per `T` gives the rate, and this section then states `N / T × 4.2 s`. It is on the mainnet launch checklist (`docs/RELEASE_CHECKLIST.md`) and has a `docs/FOLLOWUPS.md` row.

## 6. The PR sequence — RULED (HA-R6)

1. **This document.**
2. **`shekyl-hasher`, with no consumer** (rule 26: a new crate is its own PR) — BUILT (as of 2026-11-12). The actor, the cap, leases, builds, refill and the metric. Its tests are the invariant tests of §8, written against the crate's own API.
3. **The cutover, one PR, driven by the deletion** — BUILT (as of 2026-11-14). The cache store's slots were shared by every consumer in §2, so any split would have left two owners of caches in one process. The PR deleted the slot API and moved the ingest, chain sync's executor, the miner, `pow`, the node, the replay binary, the pipeline and the test harnesses onto the actor, with `ranked_seeds` and its tests.
4. **Close-out.** The live RSS capture repeated with a fork case, the floor device's `RssAnon` with three caches resident during a real initial sync, PB-R1's cache rows restated against the cap, and this document moved or made a contract (rule 95).

## 7. What holds the deletion

The cache store, the slot methods on `Substrate`, the ingest's pin lock, window install and branch gate, the executor's branch cache, and the sync model's slot-miss protocol are deleted. What keeps them from coming back is one gate, `scripts/ci/check_randomx_cache_owner.sh`:

- `PreparedCache::derive` and `Arc<PreparedCache>` appear in Rust code only under `rust/shekyl-hasher/src`, `rust/shekyl-pow-randomx/{src,benches,examples}`, `rust/shekyl-randomx-differential` and `rust/shekyl-verify-cost/benches`.
- Each allowed path must exist and still use one of them, so an allowance that names nothing fails (rule 47).
- A use anywhere else fails, naming the file and line.

`PreparedCache::derive` stays `pub`, because the actor lives above the verifier crate: that crate is held to isolation invariants a scheduler has no business under.

## 8. Tests

- **`ranked_seeds`, in isolation** (`cache_window.rs`): one table over a one-seed and a two-seed window, a held fork past its seed point, two held forks (the heavier is listed; of two equal, the first in key order), a header frontier ahead of the window, a frontier and a fork together (the more work is listed; of two equal, the fork), and a seed already in the window (not listed twice, and the next-heaviest does not take the place). A store with no block ranks nothing.
- **The invariant (HA-R5):** once the actor is quiet it holds exactly the caches a fresh actor fed the same list would hold, and no more than three caches exist at any time.
  - In the crate: the core's property test, and the same sequences through the real shell in the nightly lane.
  - On the production path: every scenario driver over `ProductionPow` checks the cap after each write and the quiet half at its close; the loopback harness gives each node a hasher of its own, checks the cap on every wait, and holds each chain's quiet hasher to a fresh one at its stop.
- **Red first, on the production path over real RandomX:**
  - a held fork past its seed point is the list's third and its cache is warm; a second span of it builds nothing; when its root leaves the cap the cache is gone at the next quiescence (`resident_tests.rs`, nightly);
  - a header run's seed is built once while the list names it and freed when the list drops it (HA-F1), and a fork proven by headers and then formed by the ingest is built once (HA-F2) (`executor_tests.rs`);
  - a switch whose blocks all carry recorded hashes builds nothing and hashes nothing (HA-F8) (`resident_tests.rs`);
  - an evidence check while the third cache is warm runs, the warm cache is freed for it, and it is back at quiescence (HA-R3) (`executor_tests.rs`);
  - an evidence check queued behind a stream of header-proof jobs for another seed runs after the one job ahead of it (HA-R8) (`executor_tests.rs`);
  - two outside-window jobs while the window names two seeds free no window seed (HA-R7) (`executor_tests.rs`);
  - a mining job whose seed leaves the list is cancelled, the worker leaves it, and the cache is freed (`miner_tests.rs`);
  - `pow` on a seed that is not warm is declined, nothing is built, and no RPC hash is spent (`rpc_store_reads_tests.rs`).
- **The boundary:** a form whose claims name one seed, run as a job on another, ends the service with `SeedNotLent` and refuses nothing; a span has one form waiting for its job at a time; a fresh store derives the null seed and block 0's and keeps one; a closed frontier ranks without it.
- **Consensus results do not move:** for the RandomX known-answer vector, `Lent::hash`, `Loan::hash`, `Loan::hash_timed` and a warm loan's hash equal the fork's output (`shekyl-hasher` `shell_tests.rs`). The differential harness's parity lanes, the verifier's vectors and every captured corpus run unchanged.
- **Carried over from #1338:** the 2,124-block nightly test, on the hasher: genesis's cache is freed once the window stops naming it (`resident_tests.rs`). The live RSS reading is step 4's.
- **The metric:** `daemon_status`'s `randomx_caches` (§5.6): a status call while the hasher holds two caches reports two, and a caller without `status` gets no part.
- **The gate** of §7, with the edit that turns each of its sides red in its header.

## 9. Wargame

- **Forced rebuilds.** A warm cache is free to hash under, so an attacker gains nothing from blocks on the most-work fork or the frontier. A block on a lighter held fork past its seed point (66 blocks of real work behind it: the seed block and the 65 above it) costs this node that fork's build and one refill, about 4.2 s on the floor device, both under the arrival's class (§5.4).
- **The evidence check.** §5.9.
- **Evicting the window's pair.** It cannot be done (§5.2).
- **Initial sync against a cheap fork.** Early blocks are cheap, so a forged run of 65 early headers earns a seed cheaply. Its proofs are jobs and get their cache; it does not hold the warm third place, which goes to the most proven work.
- **A lent cache held too long.** §5.3's types. An `Arc<PreparedCache>` outside the allowed paths fails the gate in §7.
- **The actor stalling.** §5.5: the loop itself never hashes or derives; what a job can wait for is stated there.
- **Shutdown.** §5.7.

## 10. What Round 0 read, and what it did not

Read at `cf561f79d6`, before the cutover: `cache_store.rs` (the store and its header), both `substrate.rs` files, `cache_window.rs`, `window.rs`, `span.rs`'s run, alternative and switch paths, `service.rs`'s shared state and stop, `executor.rs` whole, `peer.rs:631–:664`, the miner's work loop, `calc_pow`'s admission, the node's composition and stop order, `shekyl-hash-budget`'s header, and CS-Q2 step 3 and DX-Q2 items 1 and 6.

Not read: `switch.rs` and `plan_form.rs` beyond their call sites, the sync owner past its seed wait, the scenario harness beyond its pin sites, and `shekyl-randomx-differential`. No fleet node was read for HA-F1; the finding is from the code.
