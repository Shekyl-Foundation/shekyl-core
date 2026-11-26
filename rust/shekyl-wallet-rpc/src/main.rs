// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Standalone `shekyl-wallet-rpc` binary: the Engine-native wallet JSON-RPC
//! server, serving the contract in `docs/api/wallet_rpc.yaml`. It is the
//! only binary of that name — the C++ `wallet_rpc_server` it replaced was
//! deleted with `src/wallet/` (`a9dc5e4db`), and the transitional
//! `shekyl-engine-rpc` wallet2-FFI bridge before it. Its options are
//! `INPUT_GRAMMAR.md` §12.4 (`shekyl_wallet_rpc::table`); the listen posture
//! is `docs/design/RPC_TRANSPORT_POSTURE.md`.
#![deny(unsafe_code)]

use std::fmt::Display;
use std::io::Write as _;
use std::process::ExitCode;

use shekyl_daemon_config::exit::{EXIT_FAILED, EXIT_REFUSED};
use shekyl_options::Diagnostic;
use shekyl_wallet_rpc::config::{self, Action, Loaded};
use shekyl_wallet_rpc::table::TABLE;
use shekyl_wallet_rpc::{arm_server, check_server_config};

const PROGRAM: &str = "shekyl-wallet-rpc";

/// The note `--help` prints above the options.
const HELP_NOTE: &str = "Shekyl wallet JSON-RPC server. Values come from the command line, then \
                         the configuration file, then the defaults.";

fn exit(status: i32) -> ExitCode {
    ExitCode::from(u8::try_from(status).unwrap_or(1))
}

/// Text to standard output. A closed stream is not a panic.
fn say(text: impl Display) {
    drop(write!(std::io::stdout(), "{text}"));
}

/// A line to standard error, named for this program. A closed stream is not
/// a panic.
fn complain(line: impl Display) {
    drop(writeln!(std::io::stderr(), "{PROGRAM}: {line}"));
}

/// Say every refusal on standard error (IG-11) and exit 2.
fn refuse(faults: &[Diagnostic]) -> ExitCode {
    for fault in faults {
        complain(fault.render());
    }
    exit(EXIT_REFUSED)
}

/// The first statement is the process hardening (rule 35, DC-Q21), as in
/// `shekyld`: no core and no same-account tracer, before an argument is
/// read, the runtime started, or a wallet opened. A process that cannot
/// apply it reports the step and exits 1 without starting.
fn main() -> ExitCode {
    if let Err(e) = shekyl_process::harden::harden_process() {
        complain(format!("process hardening {e}; not starting"));
        return exit(EXIT_FAILED);
    }
    let platform = shekyl_process::platform::current();
    match config::load(std::env::args_os().skip(1), &platform) {
        Err(faults) => refuse(&faults),
        Ok(Action::Help) => {
            say(shekyl_options::help(
                &TABLE,
                PROGRAM,
                shekyl_version::RELEASE_NAME,
                shekyl_wallet_rpc::VERSION,
                HELP_NOTE,
            ));
            ExitCode::SUCCESS
        }
        Ok(Action::Version) => {
            say(format_args!("{PROGRAM} {}\n", shekyl_wallet_rpc::VERSION));
            ExitCode::SUCCESS
        }
        Ok(Action::Verify(loaded)) => verify(&loaded),
        Ok(Action::Serve(loaded)) => match serve(*loaded) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                complain(e);
                exit(EXIT_FAILED)
            }
        },
    }
}

/// `config-verify` (IG-Q63): the checks a start makes, with nothing bound or
/// created. The effective configuration is on standard output.
fn verify(loaded: &Loaded) -> ExitCode {
    if let Err(e) = check_server_config(&loaded.server) {
        complain(e);
        return exit(EXIT_REFUSED);
    }
    say(format_args!(
        "{PROGRAM}: configuration verified\n{PROGRAM}: {}\n",
        loaded.effective
    ));
    ExitCode::SUCCESS
}

/// Everything after the load: the log, the listen and auth posture, and the
/// server, on the runtime this function starts.
#[tokio::main]
async fn serve(loaded: Loaded) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Loaded {
        server,
        logging,
        effective,
        default_wallet_dir,
    } = loaded;
    let _guard = shekyl_logging::init(logging)?;
    // A required announcement (IG-14): every server start, whatever the
    // level, on standard error and in the log file when one is named.
    shekyl_logging::announce(&format!("{PROGRAM}: {effective}"), &effective);
    if let Some((root, dir)) = default_wallet_dir {
        shekyl_os_account::ensure_per_account_root(&root)
            .map_err(|e| format!("cannot create {}: {e}", root.display()))?;
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }

    // Armed before the bind, then served until a stop (SIGTERM, SIGINT,
    // SIGHUP; on Windows every console event), which closes the open
    // wallet; a second stop exits at once. The line the start owes about
    // an inherited ignore is said here, on standard error (IG-14).
    let armed = arm_server(server)?;
    if let Some(line) = armed.notice() {
        complain(line);
    }
    armed.serve().await
}
