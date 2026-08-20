// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Prints the current user's SID and nothing else.
//!
//! P-9's external cross-check compares this against `whoami /user`. It is an
//! example rather than a test because the comparison has to happen *outside*
//! the crate — a unit test that shells out to verify its own subject is
//! circular, and the whole point of the probe is an independent oracle.

fn main() {
    #[cfg(windows)]
    {
        match shekyl_win_sec::current_user_sid() {
            Ok(sid) => println!("{}", sid.as_str()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("windows-only");
        std::process::exit(1);
    }
}
