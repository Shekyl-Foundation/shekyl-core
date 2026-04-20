# shekyl-logging

Unified `tracing`-based logger initialization for Shekyl Rust
binaries, and the translation layer that will let C++ call sites
route through the same subscriber once the `easylogging++` shim is
retired in V4.

## Why this crate exists

Shekyl's logging story is mid-migration from the unmaintained C++
`easylogging++` library to [`tracing`]. The migration ships in two
chores:

- **Chore #1 (this crate, shipped in V3.1 alpha.4).** Consolidate
  the ad-hoc `tracing_subscriber::fmt().with_env_filter(...)`
  bootstraps scattered across Shekyl's Rust binaries (`shekyl-cli`,
  `shekyl-wallet-rpc`, `shekyl-daemon-rpc`) behind a single
  `shekyl_logging::init` entry point. Define the canonical env var
  (`SHEKYL_LOG`), the file-sink discipline (`0600` on POSIX for
  non-rotating sinks — see the rotation caveat below), and ship a
  stateful translator for the legacy category grammar so Chore #2
  has a hinge.
- **Chore #2 (V3.x, in progress).** Replace `MINFO` / `MDEBUG` /
  etc. macros in `src/` and `contrib/` with calls that route
  through a Rust FFI bridge into this crate. Drop
  `external/easylogging++/` from the build. Retire `MONERO_LOGS` /
  `MONERO_LOG_FORMAT` in favor of `SHEKYL_LOG`. The `size_rolling`
  file sink variant lands here as a Chore #2 prerequisite so the
  C++ daemon's legacy size-based rotation behavior carries over
  unchanged.

The translator in Chore #1 exists specifically so Chore #2 can
accept C++-originated category strings (`net.p2p:DEBUG,wallet.wallet2:INFO`,
numeric `0..=4` presets, `+`/`-` modifiers) without introducing a
second grammar in the unified logger.

## Public API

All re-exports live at the crate root; consumers should not depend
on internal module paths.

```rust
use shekyl_logging::{init, Config, FileSink, LoggerGuard};
```

### `init(config: Config) -> Result<LoggerGuard, InitError>`

Installs the global `tracing` subscriber. Idempotent per process
(subsequent calls return `InitError::AlreadyInitialized`).

### `Config`

Top-level configuration. Two helper constructors cover the two
shapes binaries actually need:

- `Config::stderr_only(fallback_default)` — stderr layer only, no
  file sink. Correct for `shekyl-cli` and for `shekyl-wallet-rpc`
  in its default (`--log-file` not passed) state.
- `Config::with_file_sink(fallback_default, FileSink)` — stderr
  layer + file sink. Correct for daemons whose default is a file
  on disk, and for `shekyl-wallet-rpc` when the operator opts in
  via `--log-file <PATH>`.

`fallback_default` is a `tracing::Level`. It is consulted only when
the `SHEKYL_LOG` env var is unset or empty at startup; setting it
explicitly prevents the "empty directive, everything logs at
subscriber baseline" landmine that plain
`tracing_subscriber::EnvFilter::from_default_env()` leaves open.

### `FileSink`

Describes a file sink. Three constructors cover the three shapes
binaries actually need:

- `FileSink::daily(directory, filename_prefix)` — rotate at UTC
  midnight via `tracing_appender`. Intended for daemons with a
  canonical log location that prefer time-based rollover.
- `FileSink::unrotated(directory, filename_prefix)` — no rotation.
  Intended for operator-owned `--log-file <PATH>` opt-ins.
- `FileSink::size_rolling(directory, filename_prefix, max_bytes,
  max_files)` — size-based rotation owned by `shekyl-logging`
  itself. Intended for the C++ daemon default sink
  (`~/.shekyl/logs/shekyld.log`, `100 MB`, `50` files) and other
  long-running binaries where the operator wants bounded on-disk
  footprint. `max_bytes = 0` disables the size check; `max_files
  = 0` disables pruning. When a rollover fires, the live file is
  renamed to `{filename_prefix}-{UTC %Y-%m-%d-%H-%M-%S}` (matching
  the legacy C++ `generate_log_filename` format) and a fresh live
  file is opened at the original path.

On POSIX:

- The sink *directory* is created with `0700` perms when
  `shekyl-logging` creates it. Pre-existing operator-managed
  directories (`--log-file /var/log/...`) are left alone.
- `FileSink::unrotated` and `FileSink::size_rolling` sinks pre-
  create the live file with mode `0600` before any event is
  written, and the size-rolling variant also re-enforces `0600`
  on every rotated file plus every newly opened live file. The
  `0600` discipline is therefore guaranteed end-to-end for both
  variants.
- The `FileSink::daily` sink (and the matching `tracing_appender`
  hourly policy) has a gap: `tracing_appender` picks the active
  filename at first write with a date/hour suffix we can't
  predict, so files created by *rotation after init* inherit the
  process umask (typically `0644`) until a later init or sweep
  runs. Prefer `size_rolling` or `unrotated` when the `0600`
  discipline must hold for the process lifetime.

### `LoggerGuard`

RAII guard for the non-blocking writer thread. Must outlive the
process's interesting work. See "The `LoggerGuard` footgun" below.

### `directives_from_legacy_categories(current, new, fallback) -> Result<TranslationReport, FilterError>`

Translator from the legacy easylogging++ `log-levels=` grammar to
an `EnvFilter` directive string. Stateful: `current` is the
currently-active spec (so `+cat:LEVEL` / `-cat` modifiers merge
textually). Process startup passes `current = None`.

Returns a `TranslationReport { directive, unknown, warnings }`.
Unknown category names are *reported*, not rejected, so callers
can choose to surface a warning without failing startup. Suffix
globs (`*y.z:LEVEL`) are rejected with
`FilterError::UnsupportedGlob` and, where possible, a suggested
rewrite.

**Empty-input semantics.** The two call sites diverge on purpose:

- `current == None` + empty `new`: startup fallback. Uses
  `fallback_default` (e.g. `WARN` for CLI, `INFO` for wallet-rpc).
- `current == Some(..)` + empty `new`: RPC/runtime toggle. Returns
  an `"off"` directive so the subsequent `EnvFilter` reload
  *silences* all logging, matching the legacy C++
  `mlog_set_categories("")` contract used by
  `TEST(logging, no_logs)`. This is not "no change".

### Env vars

| Name | Role | When honored |
|------|------|--------------|
| `SHEKYL_LOG` | Canonical filter directive | Always |
| `RUST_LOG` | Dev fallback | Only when the `dev-env-fallback` feature is on |

Release builds never honor `RUST_LOG`. A long-lived shell export
of `RUST_LOG=debug` from some other Rust project would otherwise
be a privacy foot-cannon against Shekyl binaries.

## The `LoggerGuard` footgun

`init` returns a `LoggerGuard` that must be bound to a named local
and kept alive for the duration of the binary's interesting work.
Dropping it early — or failing to bind it at all — silently
discards buffered file-sink events. The defense hierarchy, in
decreasing order of effectiveness:

1. **`#[must_use]` on `LoggerGuard`.** Primary defense. Fires on
   the common wrong idiom:

   ```rust,ignore
   // WRONG: guard dropped at the `;`, buffered events may be lost
   shekyl_logging::init(config)?;
   ```

   The correct idiom is:

   ```rust,ignore
   let _guard = shekyl_logging::init(config)?;
   // ... do work ...
   // _guard drops here, flushing any buffered events
   ```

2. **`clippy::let_underscore_must_use = "deny"` at the workspace
   root.** Secondary defense. Fires on the narrower
   `let _ = shekyl_logging::init(...)` shape. Does *not* catch the
   unbound-`?` case above; that's why `#[must_use]` is primary.

3. **This section of the README.** Neither lint catches
   `let _guard = init(...)?;` followed by code that moves
   `_guard` into an inner scope that ends mid-`main`. Only code
   review catches that shape.

4. **`tests/trybuild/must_use_unbound.rs`.** Compile-fail test
   that fails CI if a future refactor removes `#[must_use]` from
   `LoggerGuard`.

New binaries should review every `init` call against this ordering
before review approval.

## Three disclaimers

1. **Not a PII scrubber.** Whatever your call sites log,
   `shekyl-logging` will faithfully emit. PII discipline belongs
   at the `tracing::debug!` / `tracing::trace!` call site, not
   here. If an operator sets `SHEKYL_LOG=debug` against a wallet
   binary, the logger will surface everything any module chose to
   log at that level. The `tracing::debug!` / `tracing::trace!`
   macros should never be called with secret scalars, seed words,
   viewkeys, or transaction outputs in the event payload.
2. **Not `no_std`.** Requires `std`, a filesystem, and (on POSIX)
   `libc`. This crate is not intended for embedded targets.
3. **Not async-safe beyond `tracing`'s own guarantees.** The
   non-blocking writer buffers events in memory. If the binary
   exits (panic, `exit()`, signal) before the returned
   `LoggerGuard` is dropped, buffered events are lost. Graceful
   shutdown paths must let `main` return normally or explicitly
   drop the guard before calling `exit`.

## Reserved legacy target names

The preset strings used by the legacy easylogging++ numeric levels
(`0..=4`) reference two self-instrumentation targets, `logging` and
`msgwriter`. The translator preserves them verbatim so the preset's
self-instrumentation overrides survive translation. They are
**reserved**: new Rust `tracing::*` call sites must not use
`target: "logging"` or `target: "msgwriter"`. A CI test
(`tests/reserved_names.rs`) grep-enforces this against every Rust
source outside this crate.

## Versioning and stability

This crate is internal to the Shekyl workspace and is not published
to crates.io. Breaking API changes land alongside the workspace
version bumps documented in `docs/CHANGELOG.md`. Downstream
consumers should pin by path, not by semver.
