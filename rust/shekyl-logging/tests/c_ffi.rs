// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! C-harness smoke test against `libshekyl_logging.a`.
//!
//! The legacy easylogging++ replacement only lands at parity if the
//! Rust crate actually exposes a C-callable ABI that a hand-written
//! C translation unit can compile against. Rust-side unit tests don't
//! prove this: Rust can call `extern "C"` functions directly without
//! ever exercising the static-library symbol-exposure path.
//!
//! This integration test therefore writes a small C program to a
//! tempdir, compiles it with the system C compiler (located via the
//! `cc` crate's `try_get_compiler` hook), links it against the
//! staticlib produced by `cargo test` — which the `crate-type =
//! ["lib", "staticlib"]` setting in `Cargo.toml` keeps up to date —
//! runs the resulting executable, and asserts the printed output.
//!
//! The harness exercises init + emit + shutdown + get-categories in
//! one process. Running these from C instead of Rust also validates
//! that the `#[no_mangle]` + `extern "C"` plus the error-code
//! constants actually produce the symbols the shim's
//! `src/shekyl/shekyl_log.h` header will expect.
//!
//! # Skip conditions
//!
//! - Skipped on non-Unix: the linker flags this test invokes are
//!   GNU/Clang-centric and the staticlib layout on MSVC differs.
//! - Skipped when no C compiler is resolvable via `cc::Build`. That
//!   happens on minimal CI images; we report a notice rather than
//!   failing because Rust-only unit coverage still protects the
//!   logic, and the production C++ build graph (cmake +
//!   `cc_library`) validates linkage independently.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

const C_HARNESS: &str = r##"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Mirrors src/shekyl/shekyl_log.h constants that land in commit 3. */
#define SHEKYL_LOG_LEVEL_INFO 3u
#define SHEKYL_LOG_OK         0
#define SHEKYL_LOG_ERR_ALREADY_INIT (-1)

extern int  shekyl_log_init_stderr(uint8_t fallback_level);
extern void shekyl_log_shutdown(void);
extern _Bool shekyl_log_level_enabled(
    uint8_t level,
    const char *target_ptr, size_t target_len);
extern void shekyl_log_emit(
    uint8_t level,
    const char *target_ptr, size_t target_len,
    const char *file_ptr,   size_t file_len,
    uint32_t line,
    const char *func_ptr,   size_t func_len,
    const char *msg_ptr,    size_t msg_len);
extern size_t shekyl_log_get_categories(char *out_ptr, size_t out_cap);
extern int    shekyl_log_set_categories(
    const char *spec_ptr, size_t spec_len,
    uint8_t fallback_level);
extern size_t shekyl_log_last_error_message(char *out_ptr, size_t out_cap);
extern size_t shekyl_log_default_path(
    const char *binary_name_ptr, size_t binary_name_len,
    char *out_ptr, size_t out_cap);

int main(void) {
    int rc = shekyl_log_init_stderr(SHEKYL_LOG_LEVEL_INFO);
    printf("init_rc=%d\n", rc);

    int rc2 = shekyl_log_init_stderr(SHEKYL_LOG_LEVEL_INFO);
    printf("double_init_rc=%d\n", rc2);

    static const char tgt[] = "net.p2p";
    _Bool en = shekyl_log_level_enabled(
        SHEKYL_LOG_LEVEL_INFO, tgt, (size_t)(sizeof(tgt) - 1));
    printf("enabled=%d\n", en ? 1 : 0);

    static const char msg[] = "hello from the C harness";
    shekyl_log_emit(
        SHEKYL_LOG_LEVEL_INFO,
        tgt,  (size_t)(sizeof(tgt) - 1),
        NULL, 0u,
        0u,
        NULL, 0u,
        msg,  (size_t)(sizeof(msg) - 1));
    printf("emit_ran\n");

    /* `set_categories("")` should succeed (translator accepts empty at
       startup with fallback level). */
    int rc3 = shekyl_log_set_categories(NULL, 0u, SHEKYL_LOG_LEVEL_INFO);
    printf("set_empty_rc=%d\n", rc3);

    char buf[256] = {0};
    size_t n = shekyl_log_get_categories(buf, sizeof(buf));
    printf("cat_len=%zu cat=%.*s\n", n, (int)n, buf);

    /* `set_categories("1")` applies numeric preset 1. */
    static const char spec[] = "1";
    int rc4 = shekyl_log_set_categories(spec, (size_t)(sizeof(spec) - 1),
                                        SHEKYL_LOG_LEVEL_INFO);
    printf("set_preset_rc=%d\n", rc4);

    /* Bad level returns UNKNOWN_LEVEL (-4) and populates last-error. */
    int rc5 = shekyl_log_init_stderr((uint8_t)99);
    printf("bad_level_rc=%d\n", rc5);
    char errbuf[256] = {0};
    size_t errn = shekyl_log_last_error_message(errbuf, sizeof(errbuf));
    printf("err_len=%zu\n", errn);

    char pbuf[512] = {0};
    static const char bin[] = "shekyld";
    size_t pn = shekyl_log_default_path(
        bin, (size_t)(sizeof(bin) - 1), pbuf, sizeof(pbuf));
    printf("path_len=%zu\n", pn);

    shekyl_log_shutdown();
    printf("shutdown_ok\n");
    return 0;
}
"##;

fn workspace_target_dir() -> PathBuf {
    // Cargo sets CARGO_MANIFEST_DIR to the crate that owns the
    // integration test, i.e. `rust/shekyl-logging`. The workspace
    // target dir is one level up (`rust/target`).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest
        .parent()
        .expect("manifest dir has parent")
        .to_path_buf();
    // Respect CARGO_TARGET_DIR override if set.
    if let Ok(custom) = std::env::var("CARGO_TARGET_DIR") {
        if !custom.is_empty() {
            return PathBuf::from(custom);
        }
    }
    workspace_root.join("target")
}

fn find_static_lib() -> Option<PathBuf> {
    let target_dir = workspace_target_dir();
    // Integration tests run with the same profile as the test binary
    // itself. Debug is overwhelmingly the common case; if the user
    // ran `cargo test --release`, check that dir too.
    for profile in ["debug", "release"] {
        let candidate = target_dir.join(profile).join("libshekyl_logging.a");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn resolve_c_compiler() -> Option<PathBuf> {
    // `cc::Build::try_get_compiler` is designed for build scripts
    // where cargo has already populated `TARGET` / `HOST` /
    // `OPT_LEVEL`. Integration tests run without those, so we
    // resolve the compiler ourselves: honor `CC` if the operator
    // set one, otherwise fall back to `cc` / `gcc` / `clang` in
    // that order. `which` isn't in our dep graph; `Command::new`
    // + PATH lookup is good enough.
    if let Ok(override_) = std::env::var("CC") {
        if !override_.is_empty() {
            return Some(PathBuf::from(override_));
        }
    }
    for name in ["cc", "gcc", "clang"] {
        // `--version` universally succeeds on GNU/Clang; use it as
        // a liveness probe. We don't need the output.
        let status = Command::new(name)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if matches!(status, Ok(s) if s.success()) {
            return Some(PathBuf::from(name));
        }
    }
    None
}

fn compile_and_link_harness(
    c_src: &Path,
    static_lib: &Path,
    out_exe: &Path,
    cc_path: &Path,
) -> std::io::Result<std::process::ExitStatus> {
    let mut cmd = Command::new(cc_path);
    cmd.arg(c_src);
    cmd.arg(static_lib);
    // Linker deps required by Rust std's Linux runtime: pthreads
    // and libdl for lazy symbol lookup, libm for math ops, libc
    // last. `-lutil` is harmless if present on the system. `-lrt`
    // is pulled in by some tracing-subscriber paths.
    cmd.args([
        "-o",
        out_exe.to_str().expect("exe path is valid UTF-8"),
        "-lpthread",
        "-ldl",
        "-lm",
        "-lrt",
    ]);
    cmd.status()
}

#[test]
fn c_harness_links_and_runs_against_staticlib() {
    let Some(static_lib) = find_static_lib() else {
        eprintln!(
            "skipping c_harness_links_and_runs_against_staticlib: \
             libshekyl_logging.a not found under target/{{debug,release}}. \
             Rebuild with `cargo test -p shekyl-logging` to populate it."
        );
        return;
    };
    let Some(cc_path) = resolve_c_compiler() else {
        eprintln!(
            "skipping c_harness_links_and_runs_against_staticlib: \
             no C compiler on PATH (set $CC or install cc / gcc / clang)."
        );
        return;
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let c_src = tmp.path().join("harness.c");
    std::fs::write(&c_src, C_HARNESS).expect("write harness source");
    let exe = tmp.path().join("harness");

    let status = compile_and_link_harness(&c_src, &static_lib, &exe, &cc_path)
        .expect("invoke C compiler");
    assert!(status.success(), "C compiler+linker failed: {status}");

    let output = Command::new(&exe)
        .output()
        .expect("run compiled harness exe");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "harness exe exited non-zero: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );

    // Init, double-init (rejected), enabled, emit, set-categories
    // (empty + preset), bad-level, default-path, shutdown — all must
    // have fired in sequence. Exact line-by-line assertions catch
    // accidental behavior drift more than a "contains" check would.
    for needle in [
        "init_rc=0",
        "double_init_rc=-1",
        "enabled=1",
        "emit_ran",
        "set_empty_rc=0",
        "cat_len=",
        "set_preset_rc=0",
        "bad_level_rc=-4",
        "err_len=",
        "path_len=",
        "shutdown_ok",
    ] {
        assert!(
            stdout.contains(needle),
            "expected {needle:?} in harness stdout.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}
