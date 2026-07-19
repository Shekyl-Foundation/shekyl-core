# GF-7 leg-(b) sealing-run artifacts (2026-07-18/19)

Receipts artifacts and grader reports from the three sealing-run sessions of
`ARCHIVAL_BOND_WI4_MEASUREMENT.md` §19.8–§19.10, archived from `rust/target/`
so the §19.9 record's pointers stay resolvable (PR #337 closure commit).

| File | Session | Standing |
| --- | --- | --- |
| `gf7-seal-receipts-2026-07-18-withdrawn.jsonl` | first session (pre-hardening harness, 4 h 42 m) | grade **WITHDRAWN** (§19.9.1 — miner-death blindness; pre-`cadence_ms` schema, no longer grades) |
| `gf7-seal-receipts-2026-07-19-invalid.jsonl` + `gf7-seal-grade-2026-07-19-invalid.json` | hardened session 1 (4 h 41 m) | **INVALID** (§19.9.2 — negative control tripped at 0.167; counts for nothing) |
| `gf7-seal-receipts-session2.jsonl` + `gf7-seal-grade-session2-pass.json` | hardened session 2 (4 h 42 m) | **PASS** (§19.9.2 — gate row `r = 0.412`, both controls bite) |

Scope: per §19.10 the form's `K_COVER` seal-input status is withdrawn (the
`K = 2` concurrently-posting-persona premise is design-foreclosed); these are
records of a hardened instrument on its synthetic geometry, retained for the
dispersal-tripwire lineage. Re-grade with
`cargo run -p shekyl-staking-sim -- --gf7-seal <artifact>` (the two hardened
artifacts only; the withdrawn one predates the schema's period tie).
