// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The tunnel's entry: read the options, then do what they ask.

use std::io::Write;
use std::process::ExitCode;

use shekyl_rpc_transport::channel::{create_client_key, fingerprint_hex, read_client_key};
use shekyl_rpc_tunnel::config::{self, Action};
use shekyl_rpc_tunnel::{serve, table::TABLE};

fn refuse(diagnostics: &[shekyl_options::Diagnostic]) -> ExitCode {
    for diagnostic in diagnostics {
        eprintln!("{}", diagnostic.render());
    }
    ExitCode::from(2)
}

fn main() -> ExitCode {
    // The first statement is the process hardening (rule 35): no core and
    // no same-account tracer, before an argument is read or the key is.
    // A packaged unit's sandbox does not cover a tunnel started by hand.
    if let Err(error) = shekyl_process::harden::harden_process() {
        drop(writeln!(
            std::io::stderr(),
            "shekyl-rpc-tunnel: process hardening {error}; not starting"
        ));
        return ExitCode::FAILURE;
    }
    // What this process can know about an inherited ignore of a stop,
    // read before anything installs a handler: kept, and on Unix an
    // ignored SIGINT is said once; Windows names its stops on every start
    // (IG-14; Rick, 2026-11-20).
    let inherited = shekyl_process::stop::Inherited::at_start();
    let platform = shekyl_process::platform::current();
    let action = match config::load(std::env::args_os().skip(1), &platform) {
        Ok(action) => action,
        Err(diagnostics) => return refuse(&diagnostics),
    };
    match action {
        Action::Help => {
            print!(
                "{}",
                shekyl_options::help(
                    &TABLE,
                    "shekyl-rpc-tunnel",
                    shekyl_version::RELEASE_NAME,
                    shekyl_version::VERSION_FULL,
                    "Serves a node's RPC to this host's consumers over the RPC channel.",
                )
            );
            ExitCode::SUCCESS
        }
        Action::Version => {
            println!(
                "Shekyl '{}' (v{}, protocol {})\nOS: {} {}",
                shekyl_version::RELEASE_NAME,
                shekyl_version::VERSION_FULL,
                shekyl_version::PROTOCOL_VERSION,
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            ExitCode::SUCCESS
        }
        Action::KeyCreate(path) => match create_client_key(&path) {
            Ok(key) => {
                println!("{}", fingerprint_hex(key.public()));
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("{why}");
                ExitCode::FAILURE
            }
        },
        Action::KeyShow(path) => match read_client_key(&path) {
            Ok(Some(key)) => {
                println!("{}", fingerprint_hex(key.public()));
                ExitCode::SUCCESS
            }
            Ok(None) => {
                eprintln!(
                    "this tunnel has no key at {}; make one with --rpc-key-create",
                    path.display()
                );
                ExitCode::FAILURE
            }
            Err(why) => {
                eprintln!("{why}");
                ExitCode::FAILURE
            }
        },
        Action::Run(config) => run(*config, inherited),
    }
}

fn run(config: config::Config, inherited: shekyl_process::stop::Inherited) -> ExitCode {
    let key = match read_client_key(&config.key_file) {
        Ok(Some(key)) => key,
        Ok(None) => {
            eprintln!(
                "this tunnel has no key at {}; make one with --rpc-key-create, then enroll its \
                 fingerprint on the node",
                config.key_file.display()
            );
            return ExitCode::FAILURE;
        }
        Err(why) => {
            eprintln!("{why}");
            return ExitCode::FAILURE;
        }
    };
    let _guard = match shekyl_logging::init(shekyl_logging::Config {
        fallback_default: tracing::Level::WARN,
        file_sink: Some(config.logging.file_sink()),
        directive: Some(config.logging.directive()),
    }) {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("the log could not be started: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("the runtime could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(line) = inherited.line("shekyl-rpc-tunnel") {
        eprintln!("shekyl-rpc-tunnel: {line}");
    }
    match runtime.block_on(serve::run(config, inherited, key, |line| {
        println!("{line}")
    })) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            // What ended the tunnel goes to its log as well as to stderr:
            // an operator reading the log after a restart finds the
            // revocation there, at the default level.
            tracing::error!(target: "global", "{why}");
            eprintln!("{why}");
            ExitCode::FAILURE
        }
    }
}
