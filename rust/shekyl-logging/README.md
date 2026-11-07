# shekyl-logging

Unified `tracing`-based logger initialization for Shekyl Rust
binaries.

## What this crate is

One `shekyl_logging::init` entry point that every Shekyl binary
(`shekyld`, `shekyl-cli`, `shekyl-wallet-rpc`) calls instead of
building its own `tracing_subscriber` stack. It fixes the canonical
env var (`SHEKYL_LOG`), the file-sink discipline (`0600` on POSIX
for non-rotating and size-rolling sinks — see the rotation caveat
below), the queued, never-blocking sinks, and the daemon's runtime
filter changes (`subsystem::apply` for `log-level` /
`log-category`).

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
  itself, for long-running binaries where the operator wants a
  bounded on-disk footprint. `FileSink::within_budget` builds the
  daemon's from its `log-size-max` byte budget. `max_bytes = 0` disables the size check; `max_files
  = 0` disables pruning. When a rollover fires, the live file is
  renamed to `{filename_prefix}-{UTC %Y-%m-%d-%H-%M-%S}` and a fresh live
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

### Every sink is queued; a log call never blocks

Each sink — stderr always, the file when configured — sits behind its
own bounded queue (`SINK_QUEUE_LINES`, 8 192 lines) with its own writer
thread (`log-stderr`, `log-file`). A log call only enqueues. When a
sink stalls and its queue fills, further lines for that sink are
dropped and counted, never waited on; when the sink's writer catches
up it writes one line, `N lines dropped since <time>`, so the loss is
never silent: one slow stderr write (a file on a stalled disk, a slow
journald) cannot hold a logging thread, the daemon's P2P transport
workers among them.
`tests/never_blocks.rs` times each log call while the sink's write
stalls, and checks the drop report once the sink catches up.

A write the sink refuses (a dead stderr pipe, a full disk, a failing
file) is counted the same way and reported as `N lines failed to write
since <time>` once the sink takes writes again. A flush is counted only
when that `flush` returns an error, as `N flushes failed since <time>`.
A summary the sink refuses stays pending; it is not itself a failed
flush. `tests/write_errors.rs` refuses a fixed run of writes, then
accepts.

A line reaches its sink some time after the call that logged it
returns. `flush(within)` is the bounded wait: it returns `Flushed::Done`
once every line logged before the call is written and flushed, or
`Flushed::DeadlinePassed` when `within` passes first, and it never
waits on a full queue. A process about to exit calls it last (the
daemon does, after its lock's release, with `FLUSH_WITHIN`), and so
does a test that reads what a sink wrote. `tests/flush.rs` checks both
outcomes through the installed subscriber. What the queues leave
(shutdown, a bound in lines, the thread ledger) is recorded in the crate doc.

### `LoggerGuard`

RAII guard for the sinks' writer threads, one per sink. Must outlive
the process's interesting work. See "The `LoggerGuard` footgun" below.

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
3. **Not async-safe beyond `tracing`'s own guarantees.** Every
   sink's writer buffers events in memory. If the binary
   exits (panic, `exit()`, signal) before the returned
   `LoggerGuard` is dropped, buffered events are lost. Graceful
   shutdown paths must let `main` return normally or explicitly
   drop the guard before calling `exit`.

## Versioning and stability

This crate is internal to the Shekyl workspace and is not published
to crates.io. Breaking API changes land alongside the workspace
version bumps documented in `docs/CHANGELOG.md`. Downstream
consumers should pin by path, not by semver.
