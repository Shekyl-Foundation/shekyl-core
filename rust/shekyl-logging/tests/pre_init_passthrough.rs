// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pre-init C++ `M*` macros must stay audible without consuming the
//! first-caller-wins subscriber install.
//!
//! This bites against a "fix" that restores `mlog_configure("", true)`
//! inside `on_startup` or that lazy-installs a stderr subscriber on
//! the first emit: either one makes `--log-file` inert again. It does
//! NOT cover the C++ macro path (that is
//! `tests/log_file_sink.cpp` mode `pre-init-audible-then-file`).
//!
//! Own process: `INITIALIZED` is process-global.

use std::os::raw::c_char;
use std::path::PathBuf;

use shekyl_logging::ffi::{
    shekyl_log_emit, shekyl_log_init_file, shekyl_log_level_enabled, shekyl_log_shutdown,
    SHEKYL_LOG_LEVEL_ERROR, SHEKYL_LOG_LEVEL_INFO, SHEKYL_LOG_OK,
};

#[test]
fn pre_init_emit_does_not_consume_file_init() {
    // SAFETY: this integration test is the only code in the process.
    unsafe { std::env::remove_var(shekyl_logging::SHEKYL_LOG_ENV) };

    let tgt = b"global";
    // SAFETY: `tgt` is a live byte slice for the duration of each call.
    let err_on = unsafe {
        shekyl_log_level_enabled(
            SHEKYL_LOG_LEVEL_ERROR,
            tgt.as_ptr() as *const c_char,
            tgt.len(),
        )
    };
    let info_on = unsafe {
        shekyl_log_level_enabled(
            SHEKYL_LOG_LEVEL_INFO,
            tgt.as_ptr() as *const c_char,
            tgt.len(),
        )
    };
    assert!(
        err_on,
        "pre-init ERROR must be audible so wallet/daemon MERROR is not silent"
    );
    assert!(
        !info_on,
        "pre-init INFO must stay silent; the fallback floor is WARNING"
    );

    let msg = b"pre-init probe";
    // SAFETY: all pointer+length pairs describe live stack buffers, or
    // are (null, 0).
    unsafe {
        shekyl_log_emit(
            SHEKYL_LOG_LEVEL_ERROR,
            tgt.as_ptr() as *const c_char,
            tgt.len(),
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
            0,
            msg.as_ptr() as *const c_char,
            msg.len(),
        );
    }

    let dir = tempfile::tempdir().expect("tmpdir");
    let dir_s = dir.path().to_str().expect("utf8 tmpdir");
    let prefix = "pre-init-then-file.log";
    // SAFETY: `dir_s` / `prefix` are live UTF-8 slices for the call.
    let rc = unsafe {
        shekyl_log_init_file(
            dir_s.as_ptr() as *const c_char,
            dir_s.len(),
            prefix.as_ptr() as *const c_char,
            prefix.len(),
            SHEKYL_LOG_LEVEL_ERROR,
            0,
            0,
        )
    };
    assert_eq!(
        rc, SHEKYL_LOG_OK,
        "pre-init emit must not install the subscriber; file init must still win"
    );

    let post = b"post-init probe";
    // SAFETY: as the emit above.
    unsafe {
        shekyl_log_emit(
            SHEKYL_LOG_LEVEL_ERROR,
            tgt.as_ptr() as *const c_char,
            tgt.len(),
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
            0,
            post.as_ptr() as *const c_char,
            post.len(),
        );
        shekyl_log_shutdown();
    }

    let log_path: PathBuf = dir.path().join(prefix);
    assert!(
        log_path.exists(),
        "file sink was not installed at {log_path:?}"
    );
    let body = std::fs::read_to_string(&log_path).expect("read log");
    assert!(
        body.contains("post-init probe"),
        "file sink did not receive the post-init emit: {body:?}"
    );
}
