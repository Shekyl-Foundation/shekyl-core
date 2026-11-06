// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyl-shard-render`: draw one candidate.v1 PNG from a shard view.
//!
//! The web viewer (`SHARD_VIEW_FETCH.md` SV-D) runs on a host whose site is
//! not Rust. Its server route asks the site's own daemon for a shard's view
//! (`request_archival_shard` on the unrestricted listener), then hands the
//! answer to this binary, which is deployed beside the site:
//!
//! ```text
//! shekyl-shard-render [--size <px>] < view.json > shard.png
//! ```
//!
//! stdin is the daemon result (or the wallet contract's `GetShardViewResult`;
//! both carry the renderer's fields and the extra ones are ignored). stdout
//! is the PNG. Nothing else is written to stdout, so a caller may stream it
//! straight into a response body.
//!
//! Exit status is the contract: `0` with the PNG; `2` when the input is not
//! a shard view (bad JSON, a hash that is not 32 bytes of hex, a size
//! outside `MIN_RENDER_SIZE..=MAX_RENDER_SIZE`, an unknown flag) — the
//! caller's bug, with one line on stderr saying which; `1` when the render
//! itself failed. A caller that sees `2` must not retry with the same input.

use std::io::{self, Read, Write};
use std::process::ExitCode;

use shekyl_shard_visual::{
    check_render_size, render_candidate_png, ShardAggregate, MAX_RENDER_SIZE, MIN_RENDER_SIZE,
};

/// The edge length when `--size` is absent: the web gallery's sample size.
const DEFAULT_SIZE: u32 = 512;

const USAGE: &str = "usage: shekyl-shard-render [--size <px>] < view.json > shard.png";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Input(msg)) => {
            eprintln!("shekyl-shard-render: {msg}");
            ExitCode::from(2)
        }
        Err(Failure::Render(msg)) => {
            eprintln!("shekyl-shard-render: {msg}");
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    /// The caller handed us something that is not a view, or asked for a
    /// size the compositor does not draw. Not retryable with the same input.
    Input(String),
    /// A valid view the compositor could not draw, or stdout went away.
    Render(String),
}

fn run() -> Result<(), Failure> {
    let size = parse_size(std::env::args().skip(1))?;
    check_render_size(size).map_err(|e| Failure::Input(e.to_string()))?;

    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| Failure::Input(format!("stdin is not UTF-8 text: {e}")))?;
    let view: ShardAggregate =
        serde_json::from_str(&raw).map_err(|e| Failure::Input(format!("not a shard view: {e}")))?;

    let png = render_candidate_png(&view, size).map_err(|e| Failure::Render(e.to_string()))?;

    let mut out = io::stdout().lock();
    out.write_all(&png)
        .and_then(|()| out.flush())
        .map_err(|e| Failure::Render(format!("writing the PNG: {e}")))
}

/// `--size <px>` or `--size=<px>`, once; anything else is a usage error.
fn parse_size(args: impl Iterator<Item = String>) -> Result<u32, Failure> {
    let mut args = args.peekable();
    let mut size = None;
    while let Some(arg) = args.next() {
        let value = if let Some(v) = arg.strip_prefix("--size=") {
            v.to_owned()
        } else if arg == "--size" {
            args.next()
                .ok_or_else(|| Failure::Input(format!("--size needs a value\n{USAGE}")))?
        } else {
            return Err(Failure::Input(format!("unknown argument `{arg}`\n{USAGE}")));
        };
        if size.is_some() {
            return Err(Failure::Input(format!("--size given twice\n{USAGE}")));
        }
        let parsed: u32 = value.parse().map_err(|_| {
            Failure::Input(format!(
                "--size must be an integer in {MIN_RENDER_SIZE}..={MAX_RENDER_SIZE}, got `{value}`"
            ))
        })?;
        size = Some(parsed);
    }
    Ok(size.unwrap_or(DEFAULT_SIZE))
}
