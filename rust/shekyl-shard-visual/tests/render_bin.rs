// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `shekyl-shard-render` contract a web host builds against
//! (SHARD_VIEW_FETCH.md SV-D): a view on stdin becomes a PNG on stdout and
//! nothing else; a non-view is exit 2 with a stderr line; the PNG is the
//! library's own render of the same view, so the site shows what the
//! wallets show.
//!
//! Lives behind the `cli` feature with the binary it tests.

#![cfg(feature = "cli")]

use std::io::Write;
use std::process::{Command, Stdio};

use shekyl_shard_visual::{render_candidate_png, ShardAggregate};

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

fn view_json() -> String {
    // The daemon's result: the renderer's fields plus the ones only the
    // wallets read, which it must ignore.
    format!(
        r#"{{"status":"OK","shard_id":7,"shard_hash":"{}","archival_len":4000000,
            "block_count":10,"tx_count":2,"output_count":4,"coinbase_output_count":1,
            "time_range_seconds":120,"close_height":9000}}"#,
        "11".repeat(32)
    )
}

fn run(args: &[&str], stdin: &str) -> (i32, Vec<u8>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_shekyl-shard-render"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn renderer");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().expect("exit code"),
        out.stdout,
        String::from_utf8(out.stderr).expect("stderr utf-8"),
    )
}

#[test]
fn a_view_on_stdin_is_the_librarys_png_on_stdout() {
    let (code, stdout, stderr) = run(&["--size", "64"], &view_json());
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stderr.is_empty(), "nothing on stderr on success: {stderr}");
    assert!(
        stdout.starts_with(PNG_MAGIC),
        "stdout is the PNG, nothing else"
    );

    let agg: ShardAggregate = serde_json::from_str(&view_json()).expect("fixture parses");
    let expected = render_candidate_png(&agg, 64).expect("library render");
    assert_eq!(stdout, expected, "the site shows what the wallets show");
}

#[test]
fn size_defaults_to_the_gallery_edge_and_accepts_the_equals_form() {
    let (code, by_flag, _) = run(&["--size=512"], &view_json());
    assert_eq!(code, 0);
    let (code, by_default, _) = run(&[], &view_json());
    assert_eq!(code, 0);
    assert_eq!(by_flag, by_default);
}

#[test]
fn a_non_view_is_exit_2_with_the_reason_and_no_stdout() {
    let bad_hash = view_json().replace(&"11".repeat(32), "abcd");
    for (args, stdin, names) in [
        (
            vec!["--size", "64"],
            "not json".to_owned(),
            "not a shard view",
        ),
        (vec!["--size", "64"], bad_hash, "not a shard view"),
        (vec!["--size", "0"], view_json(), "invalid render size"),
        (
            vec!["--size", "huge"],
            view_json(),
            "--size must be an integer",
        ),
        (vec!["--size"], view_json(), "--size needs a value"),
        (
            vec!["--size", "8", "--size", "8"],
            view_json(),
            "given twice",
        ),
        (vec!["--png", "x"], view_json(), "unknown argument"),
    ] {
        let (code, stdout, stderr) = run(&args, &stdin);
        assert_eq!(code, 2, "{args:?}: {stderr}");
        assert!(stdout.is_empty(), "{args:?}: no partial PNG on a refusal");
        assert!(
            stderr.contains(names),
            "{args:?}: stderr names the cause: {stderr}"
        );
    }
}
