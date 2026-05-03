// Decoy selection integration tests are blocked on FCMP++ signing implementation.
//
// FCMP++ proves membership against the full UTXO set curve tree rather than selecting
// per-input ring decoys. The decoy selection algorithm (DSA) tests need to be replaced
// with curve tree snapshot validation tests once FCMP++ signing is available.
//
// When FCMP++ signing is available:
// 1. Replace ring decoy selection tests with curve tree membership proof tests
// 2. Verify that the curve tree snapshot (reference_block) is correctly selected
// 3. Run against a Shekyl regtest daemon

mod runner;
