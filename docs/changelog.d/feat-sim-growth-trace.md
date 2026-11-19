- **The economics sim traces why blocks grow under standard traffic** (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.36, GRW-1…GRW-6). This follows Rick's ruling of 2026-11-19 that the growth #1424 found is traced before EUP-4 prep.
  - **The fill's record.** Each block's fill records why it ended:
    - every offered body listed;
    - a body's fee under the penalty it adds;
    - the block's limit.

    It also records the bodies it listed past the penalty-free weight, their fees, and the block's penalty, all from production's `Fill`. Nothing a fold computes changes.
  - **`--growth-trace`.** It folds the baseline to year 40 at seed 1, on standard traffic and on `steady`, in the inherited and the re-derived zone. By period, it prints:
    - the medians and the effective median against its surge ceiling;
    - the stop reasons;
    - the penalty against the fees that paid it;
    - the pool;
    - the median count carried.

    Its narration is pinned on demand.
  - **A correction.** The reading-pass finding no longer says the daemon runs Monero's pre-v5 fill: the node's template admits through the same `Fill`.
