# Running all tests

To run all tests, run:

```bash
cd /path/to/monero
make [-jn] debug-test # where n is number of compiler processes
```

To test a release build, replace `debug-test` with `release-test` in the previous command.

# Core tests

Core tests take longer than any other Monero tests, due to the high amount of computational work involved in validating core components.

Tests are located in `tests/core_tests/`, and follow a straightforward naming convention. Most cases cover core functionality (`block_reward.cpp`, `chaingen.cpp`, `rct.cpp`, etc.), while some cover basic security tests (`double_spend.cpp` & `integer_overflow.cpp`).

To run only Monero's core tests (after building):

```bash
cd build/debug/tests/core_tests
ctest
```

To run the same tests on a release build, replace `debug` with `release`.


# Crypto Tests

Crypto tests are located under the `tests/crypto` directory.

- `crypto-tests.h` contains test harness headers
- `main.cpp` implements the driver for the crypto tests

Tests correspond to components under `src/crypto/`. A quick comparison reveals the pattern, and new tests should continue the naming convention.

To run only Monero's crypto tests (after building):

```bash
cd build/debug/tests/crypto
ctest
```

To run the same tests on a release build, replace `debug` with `release`.

# Daemon tests

[TODO]

# Functional tests

The Monero-inherited `tests/functional_tests/` Python+C++ harness was
deleted as part of the Phase 2 Electrum-words removal (see
`docs/design/ELECTRUM_WORDS_REMOVAL_PLAN.md`). It targeted
`monerod` / `monero-wallet-rpc` binary names that do not exist in
Shekyl, restored wallets via a 25-word Electrum seed (the
`restore_deterministic_wallet` JSON-RPC method removed in Phase 2),
and was already silently skipped in CI (`functional_tests_rpc` was
gated on Python deps the build environment didn't install). It was
inherited dead code with no live caller.

A Shekyl-native end-to-end harness — `shekyld` + `shekyl-wallet-rpc`
with raw-seed (`shekyl_account_generate_from_raw_seed`) restore on
testnet/fakechain — is a separate planning activity (cf.
`20-rust-vs-cpp-policy.mdc` "migration is a planning activity"). It
will live somewhere other than `tests/functional_tests/` and will be
introduced under its own design document, not as a "while we're here"
revival of this directory.

# Fuzz tests

Fuzz tests are written using American Fuzzy Lop (AFL), and located under the `tests/fuzz` directory.

An additional helper utility is provided `contrib/fuzz_testing/fuzz.sh`. AFL must be installed, and some additional setup may be necessary for the script to run properly.

# Hash tests

Hash tests exist under `tests/hash`, and include a set of target hashes in text files.

To run only Monero's hash tests (after building):

```bash
cd build/debug/tests/hash
ctest
```

To run the same tests on a release build, replace `debug` with `release`.

# Libwallet API tests

[TODO]

# Net Load tests

[TODO]

# Performance tests

Performance tests are located in `tests/performance_tests`, and test features for performance metrics on the host machine.

To run only Monero's performance tests (after building):

```bash
cd build/debug/tests/performance_tests
./performance_tests
```

The path may be build/Linux/master/debug (adapt as necessary for your platform).

If the `performance_tests` binary does not exist, try running `make` in the `build/debug/tests/performance_tests` directory.

To run the same tests on a release build, replace `debug` with `release`.

# Unit tests

Unit tests are defined under the `tests/unit_tests` directory. Independent components are tested individually to ensure they work properly on their own.

To run only Monero's unit tests (after building):

```bash
cd build/debug/tests/unit_tests
ctest
```

To run the same tests on a release build, replace `debug` with `release`.

# Writing new tests

## Test hygiene

When writing new tests, please implement all functions in `.cpp` or `.c` files, and only put function headers in `.h` files. This will help keep the fairly complex test suites somewhat sane going forward.

## Writing fuzz tests

[TODO]
