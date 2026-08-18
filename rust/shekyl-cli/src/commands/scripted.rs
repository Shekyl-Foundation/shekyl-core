// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Non-interactive wallet lifecycle for scripting / automation (WI-RPC-2a).
//!
//! The interactive REPL `create` / `restore` verbs prompt on the TTY and show
//! the seed once on screen — automation (Ansible, CI) cannot drive that. These
//! subcommands are the deliberate, auditable alternative: the password comes
//! from a file or stdin, and `create` writes the one-time seed backup to an
//! explicit `--seed-out` path (0600) instead of a terminal or a redirect. This
//! is the ONLY sanctioned way for the seed to reach a file — the interactive
//! path refuses non-TTY output rather than leak it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::rpc_client::{params, RpcSession};

type BoxErr = Box<dyn std::error::Error>;

/// `shekyl-cli create <name> --seed-out <path>` — non-interactive create.
#[derive(clap::Args)]
pub struct CreateArgs {
    /// Wallet name (file created under --engine-dir).
    pub name: String,
    /// Write the one-time seed backup to this path. Created 0600 and refuses
    /// to overwrite an existing file. Required — the server never re-exposes
    /// the seed, so it must be captured now.
    #[arg(long, value_name = "PATH")]
    pub seed_out: PathBuf,
    /// Read the wallet password from this file (a single trailing newline is
    /// stripped). Mutually exclusive with --password-stdin.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
    /// Read the wallet password from stdin (one line).
    #[arg(long)]
    pub password_stdin: bool,
}

/// `shekyl-cli restore <name> --seed-file <path>` — non-interactive restore.
#[derive(clap::Args)]
pub struct RestoreArgs {
    /// Wallet name (file created under --engine-dir).
    pub name: String,
    /// Read the seed backup from this file — a BIP-39 mnemonic
    /// (mainnet/stagenet) or a 32-byte raw seed as hex (testnet), i.e. exactly
    /// what `create --seed-out` wrote.
    #[arg(long, value_name = "PATH")]
    pub seed_file: PathBuf,
    /// Rescan floor: the block height the wallet existed at (default 0 =
    /// scan from genesis).
    #[arg(long)]
    pub restore_height: Option<u64>,
    /// Read the wallet password from this file (a single trailing newline is
    /// stripped). Mutually exclusive with --password-stdin.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
    /// Read the wallet password from stdin (one line).
    #[arg(long)]
    pub password_stdin: bool,
}

/// Create a wallet and write its one-time seed backup to `--seed-out`.
pub fn run_create(rpc: &RpcSession, args: &CreateArgs) -> Result<(), BoxErr> {
    let password = read_password_source(args.password_file.as_deref(), args.password_stdin)?;

    // Reserve the seed-out file BEFORE creating the wallet (O_EXCL, 0600): if
    // this fails we have created nothing, so there is no wallet whose backup we
    // then cannot store. If create_wallet later fails, the empty file is
    // removed on the error path below.
    let mut seed_file = open_seed_out(&args.seed_out)?;

    let result = rpc.call(
        "create_wallet",
        params::NamedPassword {
            name: &args.name,
            password: &password,
        },
    );
    drop(password);

    let val = match result {
        Ok(v) => v,
        Err(e) => {
            drop(std::fs::remove_file(&args.seed_out));
            return Err(format!("create_wallet failed: {e}").into());
        }
    };

    // Mainnet/stagenet return a BIP-39 mnemonic; testnet a raw seed as hex.
    let backup = Zeroizing::new(
        val.get("mnemonic")
            .or_else(|| val.get("raw_seed_hex"))
            .and_then(|v| v.as_str())
            .ok_or("create_wallet returned no seed backup")?
            .to_owned(),
    );
    if let Err(e) = write_seed(&mut seed_file, &backup) {
        drop(std::fs::remove_file(&args.seed_out));
        return Err(format!("failed to write seed to {}: {e}", args.seed_out.display()).into());
    }

    eprintln!(
        "Created wallet '{}'. Seed written to {} (mode 0600) — protect or delete it.",
        args.name,
        args.seed_out.display()
    );
    Ok(())
}

/// Restore a wallet from a seed file.
pub fn run_restore(rpc: &RpcSession, args: &RestoreArgs) -> Result<(), BoxErr> {
    let password = read_password_source(args.password_file.as_deref(), args.password_stdin)?;
    let seed = Zeroizing::new(
        std::fs::read_to_string(&args.seed_file)
            .map_err(|e| format!("cannot read seed file {}: {e}", args.seed_file.display()))?,
    );

    let result = rpc.call(
        "restore_wallet",
        params::Restore {
            name: &args.name,
            password: &password,
            mnemonic: seed.trim(),
            restore_height: args.restore_height.unwrap_or(0),
        },
    );
    drop(password);
    drop(seed);

    result.map_err(|e| format!("restore_wallet failed: {e}"))?;
    eprintln!("Restored wallet '{}'.", args.name);
    Ok(())
}

/// Read a password from a file or stdin into a wiped buffer. Exactly one
/// source must be given. A single trailing newline (`\n` or `\r\n`) is
/// stripped — the common shape of `echo "$PW" > file` or a piped line — but no
/// other whitespace, so a password may contain leading, internal, or
/// (non-newline) trailing spaces.
fn read_password_source(file: Option<&Path>, stdin: bool) -> Result<Zeroizing<String>, BoxErr> {
    match (file, stdin) {
        (Some(_), true) => {
            Err("--password-file and --password-stdin are mutually exclusive".into())
        }
        (None, false) => Err(
            "a password source is required: pass --password-file <path> or --password-stdin".into(),
        ),
        (Some(path), false) => {
            let mut s = Zeroizing::new(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read password file {}: {e}", path.display()))?,
            );
            strip_one_trailing_newline(&mut s);
            Ok(s)
        }
        (None, true) => {
            let mut s = Zeroizing::new(String::new());
            std::io::stdin()
                .read_line(&mut s)
                .map_err(|e| format!("cannot read password from stdin: {e}"))?;
            strip_one_trailing_newline(&mut s);
            Ok(s)
        }
    }
}

fn strip_one_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

/// Open the seed-out path 0600 with O_EXCL semantics: refuse to overwrite an
/// existing file and refuse to follow a symlink on the final component.
fn open_seed_out(path: &Path) -> Result<File, BoxErr> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            format!(
                "cannot create seed file {} (it must not already exist): {e}",
                path.display()
            )
            .into()
        })
}

fn write_seed(file: &mut File, seed: &str) -> Result<(), std::io::Error> {
    file.write_all(seed.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    // fsync so a scripted create that reports success has durably persisted the
    // only copy of the seed before the process exits.
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::strip_one_trailing_newline;

    #[test]
    fn strips_exactly_one_trailing_newline() {
        let mut s = "hunter2\n".to_string();
        strip_one_trailing_newline(&mut s);
        assert_eq!(s, "hunter2");

        let mut crlf = "hunter2\r\n".to_string();
        strip_one_trailing_newline(&mut crlf);
        assert_eq!(crlf, "hunter2");

        // Only one newline is stripped, and internal/leading spaces survive.
        let mut spaced = " pass word \n\n".to_string();
        strip_one_trailing_newline(&mut spaced);
        assert_eq!(spaced, " pass word \n");

        // No trailing newline: unchanged (supports `printf '%s'`).
        let mut bare = "nonewline".to_string();
        strip_one_trailing_newline(&mut bare);
        assert_eq!(bare, "nonewline");
    }
}
