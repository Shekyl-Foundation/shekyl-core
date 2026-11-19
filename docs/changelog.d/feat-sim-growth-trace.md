- **The economics sim traces why blocks grow under standard traffic** (`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.36, GRW-1…GRW-6). This follows Rick's ruling of 2026-11-19 that the growth #1424 found is traced before EUP-4 prep.
  - **The fill's record.** Each block's fill records why it ended:
    - every offered body listed;
    - a body's fee under the penalty it adds;
    - the block's limit.

    It also records the bodies it listed past the penalty-free weight, their fees, and the block's penalty. The split and the refusal are `Fill::admit_up_to`'s own; the block keeps the last refusal, the marginal cohort. Nothing a fold computes changes.
  - **`--growth-trace`.** It folds the baseline to year 40 at seed 1, on standard traffic and on `steady`, in the inherited and the re-derived zone. By period, it prints:
    - the medians and the effective median against its surge ceiling;
    - the stop reasons;
    - the penalty against the fees that paid it;
    - the pool;
    - the median count carried;
    - the reward minted and the penalty's share of it;
    - every listed fee per block;
    - the Standard body's weight and fee.

    Its narration is pinned on demand. It refuses every other mode, including the fee ladder, the fee floor, the secret draws, `--gate7` and `--fb1c-c2`.
  - **What it read** (§5.36.1).
    - In the inherited zone the median rests where half the blocks stop at the penalty: 68–69 bodies against a mean of 50.
    - Each body past the free weight pays its penalty, at about 0.01 % of the reward minted at rest.
    - The fee falls with the square of the LTEM's rise, which is the fee fall #1424 found.
    - The re-derived zone does not grow.
  - **A correction.** The reading-pass finding no longer says the daemon runs Monero's pre-v5 fill: the node's template admits through the same `Fill`.
