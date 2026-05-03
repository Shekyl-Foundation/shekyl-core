// Wallet send integration tests are blocked on FCMP++ signing implementation.
//
// Previously these tests used CLSAG signing against a live daemon. Since Shekyl only supports
// FCMP++ (which requires a curve tree membership proof + PQC authentication flow), the single-signer
// and multisig tests cannot execute until `SignableTransaction::sign()` is implemented.
//
// When FCMP++ signing is available:
// 1. Restore the `test!` macro invocations
// 2. Update `add_inputs` to use FCMP++ decoy/proof construction instead of ring decoys
// 3. Run against a Shekyl regtest daemon

mod runner;
