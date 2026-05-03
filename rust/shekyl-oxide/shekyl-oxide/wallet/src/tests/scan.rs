// The legacy scan test for Monero "long encrypted amount" (Original format) transactions has been
// removed. Shekyl only supports compact (8-byte) encrypted amounts with FCMP++. The old test
// vectors used V1 miner transactions and MlsagBorromean RCT types, both of which are rejected by
// Shekyl's deserializer.
//
// Integration scan tests for FCMP++ transactions should be added once a Shekyl regtest daemon
// can produce blocks with FCMP++ transactions.
